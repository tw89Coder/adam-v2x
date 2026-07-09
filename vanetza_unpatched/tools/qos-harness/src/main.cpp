#include <sys/stat.h>

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "qos_harness/amplification_profiler.hpp"
#include "qos_harness/console_presenter.hpp"
#include "qos_harness/file_manager.hpp"
#include "qos_harness/harness_engine.hpp"
#include "qos_harness/metrics_collector.hpp"
#include "qos_harness/pre_filter.hpp"
#include "qos_harness/rl_bridge.hpp"
#include "qos_harness/router_fuzzing_context.hpp"
#include "qos_harness/traffic_generator.hpp"
#include "qos_harness/dataset_builder.hpp"

// Repository filesystem paths resolving normal packets and raw attack POC binaries
const std::string REPO_ROOT_STR = REPO_ROOT;
const std::string NORMAL_FOLDER = REPO_ROOT_STR + "/inputs/base_packets";
const std::string ATTACK_FOLDER = REPO_ROOT_STR + "/inputs/attack_vectors/malware";

/**
 * @brief Prints CLI instructions mapping available parameter sweep arguments.
 */
void printHelp(const char* progName) {
    std::cout << "Usage: " << progName << " [-t total] [-p pollution_rate] [-m mode] [-f] [--build-dataset]\n"
              << "  -t               Total packets (Default: 1000000)\n"
              << "  -p               Pollution rate 0~100 (Default: 5.0)\n"
              << "  -m               Attack Mode:\n"
              << "                     0 = Uniform Random\n"
              << "                     1 = Single Pulse (30~50% window)\n"
              << "                     2 = Periodic On-Off (5 attack waves)\n"
              << "                     3 = Integrated Multi-Scenario Mix (RL Training Profile)\n"
              << "  -f               Enable Proposed Fast Pre-Filter\n"
              << "  --rl             Enable Interactive RL Training Mode (Sync via Socket)\n"
              << "  --onnx           Enable In-Process ONNX Inference Mode (Pre-compiled ONNX Model)\n"
              << "  --recovery       Override FSM Recovery Rate (AI/Custom)\n"
              << "  --penalty        Override FSM Penalty Multiplier (AI/Custom)\n"
              << "  --sq-thresh      Override FSM SQ Threshold (AI/Custom)\n"
              << "  --build-dataset  Generate and validate attack packet dataset\n"
              << "  --profile-amp    Run MTU-constrained amplification profiling\n"
              << "  --diagnose-flood Run flood region parse contribution test\n";
}

int main(int argc, char* argv[]) {
    // STANDALONE DIAGNOSTIC ONNX TESTING MODE
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--test-onnx" && i + 1 < argc) {
            std::string test_model_path = argv[++i];
            std::cout << "[TEST] Initiating standalone C++ ONNX equivalence check...\n";
            qos_harness::RLBridge bridge(REPO_ROOT_STR);
            bridge.initialize_onnx(true, test_model_path);
            bridge.set_safety_guards(false); // Disable safety guards during check to get raw model outputs
            
            // Feed 4 frames in sequence to populate the history buffer (K=4)
            // Frame 1: 1.0, 2.0, 3.0
            qos_harness::WindowTelemetry t1 = {2.0 * 65025.0, 1.0, 3.0};
            qos_harness::FilterPolicy p1;
            bridge.run_onnx_test(t1, p1);

            // Frame 2: 1.1, 2.1, 3.1
            qos_harness::WindowTelemetry t2 = {2.1 * 65025.0, 1.1, 3.1};
            bridge.run_onnx_test(t2, p1);

            // Frame 3: 1.2, 2.2, 3.2
            qos_harness::WindowTelemetry t3 = {2.2 * 65025.0, 1.2, 3.2};
            bridge.run_onnx_test(t3, p1);

            // Frame 4: 1.3, 2.3, 3.3 (this triggers final stacked state input)
            qos_harness::WindowTelemetry t4 = {2.3 * 65025.0, 1.3, 3.3};
            bridge.run_onnx_test(t4, p1);

            std::cout << "[TEST] C++ Output recovery_rate: " << p1.recovery_rate << "\n";
            std::cout << "[TEST] C++ Output penalty_multiplier: " << p1.penalty_multiplier << "\n";
            std::cout << "[TEST] C++ Output sq_threshold: " << p1.sq_threshold << "\n";
            std::cout << "[TEST] C++ Output base_sampling_rate: " << p1.base_sampling_rate << "\n";
            return 0;
        }
    }

    // Default simulation and mitigation parameters
    int total_packets = 1000000;
    double pollution_rate = 5.0;
    int attack_mode = 0;
    bool enable_filter = false;
    bool build_dataset = false;
    bool profile_amp = false;
    bool diagnose_flood = false;
    bool rl_train_mode = false;
    bool enable_onnx = false;
    std::string onnx_model_path = "";
    bool disable_safety = false;
    bool has_custom_policy = false;
    bool enable_trace = false;
    unsigned int seed = 42;

    // Hardcoded static fallback parameters for local overrides
    double custom_recovery = 0.05;
    double custom_penalty = 50.0;
    int custom_sq_thresh = 600;

    // Parse runtime arguments and configure evaluation profiles
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h") {
            printHelp(argv[0]);
            return 0;
        } else if (arg == "--build-dataset") {
            build_dataset = true;
        } else if (arg == "--profile-amp") {
            profile_amp = true;
        } else if (arg == "--diagnose-flood") {
            diagnose_flood = true;
        } else if (arg == "--rl") {
            rl_train_mode = true;
            enable_filter = true; // Training DRL implies enabling the adaptive FSM pre-filter
        } else if (arg == "--onnx" && i + 1 < argc) {
            enable_onnx = true;
            onnx_model_path = argv[++i];
            enable_filter = true;
        } else if (arg == "--disable-safety") {
            disable_safety = true;
        } else if (arg == "-f") {
            enable_filter = true;
        } else if (arg == "--recovery" && i + 1 < argc) {
            custom_recovery = std::atof(argv[++i]);
            has_custom_policy = true;
        } else if (arg == "--penalty" && i + 1 < argc) {
            custom_penalty = std::atof(argv[++i]);
            has_custom_policy = true;
        } else if (arg == "--sq-thresh" && i + 1 < argc) {
            custom_sq_thresh = std::atoi(argv[++i]);
            has_custom_policy = true;
        } else if (arg == "-t" && i + 1 < argc) {
            total_packets = std::atoi(argv[++i]);
        } else if (arg == "-p" && i + 1 < argc) {
            pollution_rate = std::atof(argv[++i]);
        } else if (arg == "-m" && i + 1 < argc) {
            attack_mode = std::atoi(argv[++i]);
        } else if (arg == "--trace") {
            enable_trace = true;
        } else if (arg == "--seed" && i + 1 < argc) {
            seed = std::atoi(argv[++i]);
        }
    }
    
    // Configure simulation random seed
    srand(seed);
    std::cout << "[*] Configured simulation random seed: " << seed << "\n";
    
    // Defensive check: Assert ONNX cannot run without FSM pre-filter enabled
    if (enable_onnx && !enable_filter) {
        std::cerr << "[-] Error: ONNX mode (--onnx) and disabled filter (without -f) are mutually exclusive.\n";
        return 1;
    }

    // Ingest baseline standards-compliant packets
    auto normals = qos_harness::FileManager::loadPacketsFromFolder(NORMAL_FOLDER);
    if (normals.empty()) {
        std::cerr << "[-] Error: No normal packets found in " << NORMAL_FOLDER << "/\n";
        return 1;
    }
    vanetza::ByteBuffer base_normal = normals[0];
    std::cout << "[*] Loaded base normal packet: " << base_normal.size() << " bytes\n";

    // Load reference toxic ASN.1 mutation representing base CWE-674 exploit
    std::string poc_path = REPO_ROOT_STR + "/inputs/attack_vectors/malware/poc_mtu_limit.bin";
    vanetza::ByteBuffer poc_packet = qos_harness::FileManager::readFileIntoBuffer(poc_path);
    if (poc_packet.empty()) {
        std::cerr << "[-] poc_mtu_limit.bin missing\n";
        return 1;
    }

    // Diagnostics / Profiling modes exit early after computing local metrics
    if (profile_amp) {
        qos_harness::AmplificationProfiler::runAmplificationProfiling(poc_packet);
        return 0;
    }
    if (diagnose_flood) {
        qos_harness::AmplificationProfiler::runFloodDiagnosis(poc_packet);
        return 0;
    }
    if (build_dataset) {
        return qos_harness::DatasetBuilder::build(base_normal, poc_packet) ? 0 : 1;
    }

    // Load attack dataset generated via offline fuzzer
    auto attack_packets = qos_harness::FileManager::loadPacketsFromFolder(ATTACK_FOLDER);
    if (attack_packets.empty()) {
        std::cerr << "[-] No attack packets found in " << ATTACK_FOLDER << "/\n";
        std::cerr << "[-] Run with --build-dataset first.\n";
        return 1;
    }
    std::cout << "[*] Loaded " << attack_packets.size() << " attack packet variants from " << ATTACK_FOLDER << "/\n";

    auto normal_packets = qos_harness::FileManager::loadPacketsFromFolder(NORMAL_FOLDER);
    std::cout << "[*] Loaded " << normal_packets.size() << " normal packet variants from " << NORMAL_FOLDER << "/\n";

    // Generate stochastic execution schedule to decouple packet routing ordering
    std::vector<unsigned int> sequence(total_packets);
    for (int i = 0; i < total_packets; ++i) {
        sequence[i] = static_cast<unsigned int>(rand());
    }

    // Determine current build directory to classify output folders
    std::string prog_path = argv[0];
    std::string build_type = "unpatched";
    if (prog_path.find("vanetza_patched") != std::string::npos) {
        build_type = "patched";
    }

    // Initialize raw telemetry directories
    std::string base_out_dir = REPO_ROOT_STR + "/outputs";
    std::string csv_base_dir = base_out_dir + "/csv_raw";
    std::string csv_target_dir = csv_base_dir + "/" + build_type;

    mkdir(base_out_dir.c_str(), 0755);
    mkdir(csv_base_dir.c_str(), 0755);
    mkdir(csv_target_dir.c_str(), 0755);

    // Format target file path for output logging
    char out_filename[512];
    if (pollution_rate == 0.0) {
        std::snprintf(out_filename, sizeof(out_filename), "%s/qos_baseline.csv", csv_target_dir.c_str());
    } else if (enable_filter) {
        if (rl_train_mode) {
            std::snprintf(out_filename, sizeof(out_filename), "%s/qos_attack_%.1f_mode%d_rl.csv",
                          csv_target_dir.c_str(), pollution_rate, attack_mode);
        } else if (enable_onnx) {
            std::snprintf(out_filename, sizeof(out_filename), "%s/qos_attack_%.1f_mode%d_onnx.csv",
                          csv_target_dir.c_str(), pollution_rate, attack_mode);
        } else {
            std::snprintf(out_filename, sizeof(out_filename), "%s/qos_attack_%.1f_mode%d_filtered.csv",
                          csv_target_dir.c_str(), pollution_rate, attack_mode);
        }
    } else {
        std::snprintf(out_filename, sizeof(out_filename), "%s/qos_attack_%.1f_mode%d.csv", csv_target_dir.c_str(),
                      pollution_rate, attack_mode);
    }

    std::cout << "[*] Mode: " << attack_mode << " | Rate: " << pollution_rate
              << "% | Filter: " << (enable_filter ? "ON" : "OFF")
              << " | ONNX: " << (enable_onnx ? "ON" : "OFF") << "\n";
    std::cout << "[*] Starting QoS Measurement...\n";
    if (enable_filter) {
        std::cout << "[*] Metric Legend: Insp[A/T] = Inspection Rate [Actual / Target]\n";
    }

    // Initialize the main mitigation state machine
    AdaptiveFilterFSM filter_fsm;

    // Apply custom parameters if CLI override flags were provided
    if (has_custom_policy) {
        filter_fsm.update_policy_params(custom_recovery, custom_penalty, custom_sq_thresh, 0.10);
        std::cout << "[+] Policy Override Active -> Recovery: " << custom_recovery << " | Penalty: " << custom_penalty
                  << " | SQ Thresh: " << custom_sq_thresh << " | S0 Sampling: 0.10\n";
    }

    // Initialize socket co-simulation bridge for active DRL co-processing
    qos_harness::RLBridge rl_bridge(REPO_ROOT_STR);
    if (disable_safety) {
        rl_bridge.set_safety_guards(false);
    }
    rl_bridge.initialize_onnx(enable_onnx, onnx_model_path);
    if (enable_trace || rl_train_mode || enable_onnx) {
        rl_bridge.initialize(rl_train_mode, pollution_rate, attack_mode, enable_trace);
    }

    vanetza::RouterFuzzingContext context;

    qos_harness::MetricsCollector collector;
    collector.reserve(total_packets);

    // Performance metrics and timeline tracking
    int true_positives = 0, false_positives = 0, true_negatives = 0, false_negatives = 0;
    int mode1_start = total_packets * 0.3;
    int mode1_end = total_packets * 0.5;
    int mode2_period = total_packets / 10;
    int print_interval = total_packets / 100;
    int malware_so_far = 0;

    // Used to track the total number of packets sampled by FSM
    int total_inspected = 0;

    // Convert pollution rate percentage into basis points (0.01% resolution)
    // Ensures sub-1.0% pollution rates (e.g. 0.1%, 0.5%) map to accurate integer ranges
    unsigned int target_basis_threshold = static_cast<unsigned int>(pollution_rate * 100.0);

    // Main packet generation and processing iteration loop
    for (int i = 0; i < total_packets; ++i) {
        if (i % print_interval == 0 || i == total_packets - 1) {
            // Calculate current actual and target sampling rates
            double actual_avg_rate = (i > 0) ? (static_cast<double>(total_inspected) / i) * 100.0 : 0.0;
            double current_target_rate = enable_filter ? filter_fsm.get_sampling_rate() * 100.0 : 0.0;
            
            // Call the console presenter
            qos_harness::ConsolePresenter::printSimulationProgress(
                i, total_packets, malware_so_far, 
                enable_filter, actual_avg_rate, current_target_rate
            );
        }

        // Determine if current packet slot contains an attack variant based on the active mode schedule
        bool is_malware = false;
        if (attack_mode == 0) {
            // Mode 0: Uniform Random distribution across the entire trajectory
            is_malware = (sequence[i] % 10000) < target_basis_threshold;
        } else if (attack_mode == 1) {
            // Mode 1: Single attack burst occurring between 30% and 50% timelines
            if (i >= mode1_start && i <= mode1_end) is_malware = (sequence[i] % 10000) < target_basis_threshold;
        } else if (attack_mode == 2) {
            // Mode 2: Periodic On-Off waves (attack waves repeat every mode2_period steps)
            int current_cycle = i / mode2_period;
            if (current_cycle % 2 == 1) is_malware = (sequence[i] % 10000) < target_basis_threshold;
        } else if (attack_mode == 3) {
            // Mode 3: Integrated Multi-Scenario Mix (Default training pattern)
            //   0.0 - 0.2: Clean peacetime nominal traffic
            //   0.2 - 0.5: Continuous uniform attack storm
            //   0.5 - 0.7: Peacetime recovery window
            //   0.7 - 1.0: Periodic oscillating pulsing attacks
            double progress = static_cast<double>(i) / total_packets;
            if (progress < 0.2) {
                is_malware = false;
            } else if (progress < 0.5) {
                is_malware = (sequence[i] % 10000) < target_basis_threshold;
            } else if (progress < 0.7) {
                is_malware = false;
            } else {
                int current_cycle = i / mode2_period;
                if (current_cycle % 2 == 1) is_malware = (sequence[i] % 10000) < target_basis_threshold;
            }
        }

        if (is_malware) malware_so_far++;

        // Route packet payload from normal or attack dataset vectors
        const vanetza::ByteBuffer& buf = is_malware ? attack_packets[sequence[i] % attack_packets.size()]
                                                    : normal_packets[sequence[i] % normal_packets.size()];

        // Execute parsing and record processing latency
        auto start = std::chrono::high_resolution_clock::now();
        bool drop_packet = enable_filter ? filter_fsm.process_packet(buf) : false;

        // If the filter is enabled and the packet is indeed sampled, increment the count.
        if (enable_filter && filter_fsm.was_inspected()) {
            total_inspected++;
        }

        // Classification metric routing
        if (drop_packet) {
            if (is_malware)
                true_positives++;
            else
                false_positives++;
        } else {
            if (is_malware)
                false_negatives++;
            else
                true_negatives++;
            // Pass allowed packets to the mock router logic indicate method
            vanetza::ByteBuffer buf_copy = buf;
            context.indicate(std::move(buf_copy));
        }
        auto end = std::chrono::high_resolution_clock::now();
        long long latency_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

        // Log packet results
        collector.recordPacket(i, is_malware, drop_packet, latency_ns);

        // Interactive Online DRL Bridge interface synchronization check
        if (enable_filter) {
            if (enable_trace || rl_train_mode || enable_onnx) {
                // Buffer packet stats and evaluate window boundary splits
                rl_bridge.collect_packet_telemetry(buf.size(), filter_fsm.get_last_sq(), filter_fsm.current_budget,
                                                   static_cast<int>(filter_fsm.get_state()), drop_packet, is_malware,
                                                   filter_fsm.was_inspected(), filter_fsm.get_last_latency_ticks());
            }
            if (rl_train_mode || enable_onnx) {
                rl_bridge.check_and_sync_window(i, filter_fsm);
            }
        }
    }

    std::cout << "\n[*] Simulation complete. Writing data to disk...\n";
    collector.exportToCSV(out_filename);

    if (enable_filter) {
        qos_harness::ConsolePresenter::printSecurityReport(total_packets, malware_so_far, true_positives,
                                                           true_negatives, false_positives, false_negatives);
    }

    std::cout << qos_harness::ConsolePresenter::green() << "[+] Saved to " << out_filename
              << qos_harness::ConsolePresenter::reset() << "\n";
    return 0;
}