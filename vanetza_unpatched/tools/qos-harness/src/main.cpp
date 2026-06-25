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

const int DATASET_TARGET = 1000;
const int MAX_ATTEMPTS = 1000000;

const std::string REPO_ROOT_STR = REPO_ROOT;
const std::string NORMAL_FOLDER = REPO_ROOT_STR + "/inputs/base_packets";
const std::string ATTACK_FOLDER = REPO_ROOT_STR + "/inputs/attack_vectors/malware";

bool buildAttackDataset(const vanetza::ByteBuffer& base_normal, const vanetza::ByteBuffer& poc_packet) {
    mkdir(ATTACK_FOLDER.c_str(), 0755);
    std::cout << "[*] Profiling base POC packet latency baseline...\n";

    long long poc_total_ns = 0;
    for (int i = 0; i < 10; ++i) {
        long long lat = qos_harness::HarnessEngine::measurePacketLatency(poc_packet);
        if (lat < 0) return false;
        poc_total_ns += lat;
    }

    long long latency_threshold = static_cast<long long>((poc_total_ns / 10) * 1.05);
    int generated = 0, attempts = 0, rejected = 0;

    std::cout << "[+] Base POC Mean Latency: " << (poc_total_ns / 10) << " ns\n";
    std::cout << "[*] Performance Threshold set to: " << latency_threshold << " ns\n";
    std::cout << "[*] Building attack dataset (Target: " << DATASET_TARGET << " verified SLOW packets)...\n";

    while (generated < DATASET_TARGET && attempts < MAX_ATTEMPTS) {
        attempts++;

        unsigned int seed = static_cast<unsigned int>(time(nullptr)) ^ (attempts * 2654435761u);
        vanetza::ByteBuffer candidate = qos_harness::TrafficGenerator::craftAttackPacket(poc_packet, seed);

        bool consistently_potent = true;
        long long running_lat_sum = 0;
        const int VERIFICATION_RUNS = 3;

        for (int v = 0; v < VERIFICATION_RUNS; ++v) {
            long long sample_lat = qos_harness::HarnessEngine::measurePacketLatency(candidate);
            if (sample_lat < latency_threshold) {
                consistently_potent = false;
                break;
            }
            running_lat_sum += sample_lat;
        }

        if (consistently_potent) {
            long long confirmed_avg_lat = running_lat_sum / VERIFICATION_RUNS;
            char path[256];
            std::snprintf(path, sizeof(path), "%s/attack_%05d.bin", ATTACK_FOLDER.c_str(), generated);
            qos_harness::FileManager::writeBufferToFile(path, candidate);
            generated++;

            if (generated % 10 == 0 || generated == DATASET_TARGET) {
                qos_harness::ConsolePresenter::printDatasetProgress(generated, DATASET_TARGET, rejected,
                                                                    confirmed_avg_lat);
            }
        } else {
            rejected++;
            if (attempts % 1000 == 0) {
                std::printf("\r  [*] Searching... Potent Found: %4d/%-4d | Rejects: %-7d\033[K", generated,
                            DATASET_TARGET, rejected);
                std::fflush(stdout);
            }
        }
    }

    std::cout << "\n";
    if (generated < DATASET_TARGET) {
        std::cout << "[!] Warning: only generated " << generated << "/" << DATASET_TARGET << " packets after "
                  << attempts << " attempts.\n";
        return generated > 0;
    }

    std::cout << qos_harness::ConsolePresenter::green() << "[+] Dataset complete: " << generated
              << " attack packets saved to " << ATTACK_FOLDER << qos_harness::ConsolePresenter::reset() << "/\n";
    std::cout << qos_harness::ConsolePresenter::red()
              << "[+] Vanetza rejection rate during generation: " << (rejected * 100.0 / attempts) << "%"
              << qos_harness::ConsolePresenter::reset() << "\n";
    return true;
}

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
              << "  --recovery       Override FSM Recovery Rate (AI/Custom)\n"
              << "  --penalty        Override FSM Penalty Multiplier (AI/Custom)\n"
              << "  --sq-thresh      Override FSM SQ Threshold (AI/Custom)\n"
              << "  --build-dataset  Generate and validate attack packet dataset\n"
              << "  --profile-amp    Run MTU-constrained amplification profiling\n"
              << "  --diagnose-flood Run flood region parse contribution test\n";
}

int main(int argc, char* argv[]) {
    int total_packets = 1000000;
    double pollution_rate = 5.0;
    int attack_mode = 0;
    bool enable_filter = false;
    bool build_dataset = false;
    bool profile_amp = false;
    bool diagnose_flood = false;
    bool rl_train_mode = false;
    bool has_custom_policy = false;

    double custom_recovery = 0.05;
    double custom_penalty = 50.0;
    int custom_sq_thresh = 600;

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
            enable_filter = true;  // Force-enable filter pipelines under active RL training
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
        }
    }

    auto normals = qos_harness::FileManager::loadPacketsFromFolder(NORMAL_FOLDER);
    if (normals.empty()) {
        std::cerr << "[-] Error: No normal packets found in " << NORMAL_FOLDER << "/\n";
        return 1;
    }
    vanetza::ByteBuffer base_normal = normals[0];
    std::cout << "[*] Loaded base normal packet: " << base_normal.size() << " bytes\n";

    std::string poc_path = REPO_ROOT_STR + "/inputs/attack_vectors/malware/poc_mtu_limit.bin";
    vanetza::ByteBuffer poc_packet = qos_harness::FileManager::readFileIntoBuffer(poc_path);
    if (poc_packet.empty()) {
        std::cerr << "[-] poc_mtu_limit.bin missing\n";
        return 1;
    }

    if (profile_amp) {
        qos_harness::AmplificationProfiler::runAmplificationProfiling(poc_packet);
        return 0;
    }
    if (diagnose_flood) {
        qos_harness::AmplificationProfiler::runFloodDiagnosis(poc_packet);
        return 0;
    }
    if (build_dataset) {
        return buildAttackDataset(base_normal, poc_packet) ? 0 : 1;
    }

    auto attack_packets = qos_harness::FileManager::loadPacketsFromFolder(ATTACK_FOLDER);
    if (attack_packets.empty()) {
        std::cerr << "[-] No attack packets found in " << ATTACK_FOLDER << "/\n";
        std::cerr << "[-] Run with --build-dataset first.\n";
        return 1;
    }
    std::cout << "[*] Loaded " << attack_packets.size() << " attack packet variants from " << ATTACK_FOLDER << "/\n";

    auto normal_packets = qos_harness::FileManager::loadPacketsFromFolder(NORMAL_FOLDER);
    std::cout << "[*] Loaded " << normal_packets.size() << " normal packet variants from " << NORMAL_FOLDER << "/\n";

    std::vector<unsigned int> sequence(total_packets);
    for (int i = 0; i < total_packets; ++i) {
        sequence[i] = static_cast<unsigned int>(rand());
    }

    // =========================================================================
    // INTEGRATED: Smart directory router to completely bifurcate test matrices
    // =========================================================================
    std::string prog_path = argv[0];
    std::string build_type = "unpatched";
    if (prog_path.find("vanetza_patched") != std::string::npos) {
        build_type = "patched";
    }

    std::string base_out_dir = REPO_ROOT_STR + "/outputs";
    std::string csv_base_dir = base_out_dir + "/csv_raw";
    std::string csv_target_dir = csv_base_dir + "/" + build_type;

    mkdir(base_out_dir.c_str(), 0755);
    mkdir(csv_base_dir.c_str(), 0755);
    mkdir(csv_target_dir.c_str(), 0755);

    char out_filename[512];
    if (pollution_rate == 0.0) {
        std::snprintf(out_filename, sizeof(out_filename), "%s/qos_baseline.csv", csv_target_dir.c_str());
    } else if (enable_filter) {
        std::snprintf(out_filename, sizeof(out_filename), "%s/qos_attack_%.1f_mode%d_filtered.csv",
                      csv_target_dir.c_str(), pollution_rate, attack_mode);
    } else {
        std::snprintf(out_filename, sizeof(out_filename), "%s/qos_attack_%.1f_mode%d.csv", csv_target_dir.c_str(),
                      pollution_rate, attack_mode);
    }

    std::cout << "[*] Mode: " << attack_mode << " | Rate: " << pollution_rate
              << "% | Filter: " << (enable_filter ? "ON" : "OFF") << "\n";
    std::cout << "[*] Starting QoS Measurement...\n";

    AdaptiveFilterFSM filter_fsm;

    if (has_custom_policy) {
        filter_fsm.update_policy_params(custom_recovery, custom_penalty, custom_sq_thresh);
        std::cout << "[+] Policy Override Active -> Recovery: " << custom_recovery << " | Penalty: " << custom_penalty
                  << " | SQ Thresh: " << custom_sq_thresh << "\n";
    }

    qos_harness::RLBridge rl_bridge(REPO_ROOT_STR);
    rl_bridge.initialize(rl_train_mode, pollution_rate, attack_mode);

    vanetza::RouterFuzzingContext context;

    qos_harness::MetricsCollector collector;
    collector.reserve(total_packets);

    int true_positives = 0, false_positives = 0, true_negatives = 0, false_negatives = 0;
    int mode1_start = total_packets * 0.3;
    int mode1_end = total_packets * 0.5;
    int mode2_period = total_packets / 10;
    int print_interval = total_packets / 20;
    int malware_so_far = 0;

    for (int i = 0; i < total_packets; ++i) {
        if (i % print_interval == 0 || i == total_packets - 1) {
            qos_harness::ConsolePresenter::printSimulationProgress(i, total_packets, malware_so_far);
        }

        bool is_malware = false;
        if (attack_mode == 0) {
            is_malware = (sequence[i] % 100) < static_cast<unsigned int>(pollution_rate);
        } else if (attack_mode == 1) {
            if (i >= mode1_start && i <= mode1_end)
                is_malware = (sequence[i] % 100) < static_cast<unsigned int>(pollution_rate);
        } else if (attack_mode == 2) {
            int current_cycle = i / mode2_period;
            if (current_cycle % 2 == 1) is_malware = (sequence[i] % 100) < static_cast<unsigned int>(pollution_rate);
        } else if (attack_mode == 3) {
            double progress = static_cast<double>(i) / total_packets;
            if (progress < 0.2) {
                is_malware = false;  // Phase 1: Pure static baseline
            } else if (progress < 0.5) {
                is_malware = (sequence[i] % 100) < static_cast<unsigned int>(pollution_rate);  // Phase 2: Pulse storm
            } else if (progress < 0.7) {
                is_malware = false;  // Phase 3: Immediate cease-fire
            } else {
                int current_cycle = i / mode2_period;  // Phase 4: Intermittent wave sequences
                if (current_cycle % 2 == 1)
                    is_malware = (sequence[i] % 100) < static_cast<unsigned int>(pollution_rate);
            }
        }

        if (is_malware) malware_so_far++;

        const vanetza::ByteBuffer& buf = is_malware ? attack_packets[sequence[i] % attack_packets.size()]
                                                    : normal_packets[sequence[i] % normal_packets.size()];

        auto start = std::chrono::high_resolution_clock::now();
        bool drop_packet = enable_filter ? filter_fsm.process_packet(buf) : false;

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
            vanetza::ByteBuffer buf_copy = buf;
            context.indicate(std::move(buf_copy));
        }
        auto end = std::chrono::high_resolution_clock::now();
        long long latency_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

        collector.recordPacket(i, is_malware, drop_packet, latency_ns);

        if (enable_filter) {
            // CRITICAL PERF GUARD: Only execute disk I/O and telemetry logging
            // when explicitly running under interactive reinforcement learning training mode.
            if (rl_train_mode) {
                // Collect per-packet metrics for state/reward profiling
                rl_bridge.collect_packet_telemetry(buf.size(), filter_fsm.get_last_sq(), filter_fsm.current_budget,
                                                   static_cast<int>(filter_fsm.get_state()), drop_packet);

                // Trigger window boundary checks and blocking loopback socket sync
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