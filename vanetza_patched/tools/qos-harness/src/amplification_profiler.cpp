/**
 * @file amplification_profiler.cpp
 * @brief Implementation of the V2X parsing latency profiler and flood region diagnostic tool.
 * 
 * DESIGN CONTEXT & ARCHITECTURAL ROLE:
 * This module measures, diagnoses, and profiles parser CPU workload amplification 
 * factors. It compares baseline standards-compliant packets with mutated 
 * ASN.1 recursion exploits (CWE-674) to quantify performance degradation and 
 * establish defensive benchmarks under strict Maximum Transmission Unit (MTU) barriers.
 * 
 * PROFILING METHODOLOGY:
 * - Benchmarks processing latencies by feeding packet payloads to the parser harness.
 * - Simulates mutated payloads by grafting various structural flood strategies onto the 
 *   ASN.1 exploit header region.
 * - Sweeps total packet sizes up to the MTU limit (1400 bytes) to characterize the scaling 
 *   factor of structural recursion amplification.
 */

#include "qos_harness/amplification_profiler.hpp"

#include <sys/stat.h>
#include <dirent.h>

#include <algorithm>
#include <climits>
#include <cmath>
#include <fstream>
#include <iostream>
#include <vector>

#include "qos_harness/console_presenter.hpp"
#include "qos_harness/file_manager.hpp"
#include "qos_harness/harness_engine.hpp"
#include "qos_harness/traffic_generator.hpp"

namespace qos_harness {

namespace {

/**
 * @brief Telemetry results representing a baseline packet latency benchmark.
 */
struct BaselineResult {
    long long avg_ns;       // Average parsing duration in nanoseconds
    long long median_ns;    // Median parsing duration in nanoseconds
    long long min_ns;       // Minimum observed latency in nanoseconds
    long long max_ns;       // Maximum observed latency in nanoseconds
    int valid_runs;         // Count of successful parsing trials
    int crashed_runs;       // Count of trials resulting in parser errors or crashes
};

/**
 * @brief Telemetry results representing a fuzzed size probe execution.
 */
struct ProbeResult {
    long long avg_ns;       // Average latency in nanoseconds
    long long median_ns;    // Median latency in nanoseconds
    long long min_ns;       // Minimum observed latency
    long long max_ns;       // Maximum observed latency
    int valid_runs;         // Successful parsing runs
    int crashed_runs;       // Parser rejection runs
    bool sufficient;        // True if the minimum valid runs requirement was met
    vanetza::ByteBuffer best_packet;
    int best_strategy_idx;
    std::string best_strategy_name;
    int recursion_depth;
};

const size_t MTU_LIMIT = 1400;              // Standard MTU capacity ceiling
const double SIZE_STEP_FACTOR = 1.10;       // Multiplier for geometric size progressions
const size_t EXPLOIT_HEADER_SIZE = 64;      // exploit offset separating the structural headers

/**
 * @brief Measures latency statistics for a packet buffer across repeated benchmark trials.
 * 
 * @param pkt Packet byte buffer payload.
 * @param runs Total count of parsing runs.
 * @param label Console output prefix string.
 * @return BaselineResult containing latency statistics.
 */
BaselineResult measureRepeatedLatency(const vanetza::ByteBuffer& pkt, int runs, const std::string& label) {
    BaselineResult r = {0, 0, LLONG_MAX, 0, 0, 0};
    std::vector<long long> samples;
    samples.reserve(runs);

    for (int i = 0; i < runs; i++) {
        long long lat = HarnessEngine::measurePacketLatency(pkt);
        if (lat > 0) {
            samples.push_back(lat);
            r.min_ns = std::min(r.min_ns, lat);
            r.max_ns = std::max(r.max_ns, lat);
            r.valid_runs++;
        } else {
            r.crashed_runs++;
        }
        
        // Output progress based on size and category classification labels every 100 runs
        if ((i + 1) % 100 == 0 || (i + 1) == runs) {
            long long current_med = !samples.empty() ? samples[samples.size() / 2] : 0LL;
            if (pkt.size() <= 400 && label == "baseline") {
                ConsolePresenter::printBaselineProgress("baseline", i + 1, runs, r.valid_runs, r.crashed_runs,
                                                        lat > 0 ? lat : 0LL);
            } else if (label == "baseline") {
                ConsolePresenter::printBaselineProgress("probing ", i + 1, runs, r.valid_runs, r.crashed_runs,
                                                        lat > 0 ? lat : 0LL);
            } else {
                ConsolePresenter::printVariantProgress(label, i + 1, runs, r.valid_runs, r.crashed_runs,
                                                       lat > 0 ? lat : 0LL);
            }
        }
    }

    if (samples.empty()) return r;
    long long total = 0;
    for (const long long s : samples) total += s;
    r.avg_ns = total / (long long)samples.size();

    // Sort to extract the median latency sample
    std::sort(samples.begin(), samples.end());
    r.median_ns = samples[samples.size() / 2];
    return r;
}

/**
 * @brief Computes a geometric sequence of target packet sizes up to the MTU capacity limit.
 * 
 * @param poc_size Starting packet size in bytes.
 * @return Vector of target sizes in bytes.
 */
std::vector<size_t> buildSizeSteps(size_t poc_size) {
    std::vector<size_t> steps;
    double total = static_cast<double>(poc_size);
    steps.push_back(poc_size);
    while (true) {
        total *= SIZE_STEP_FACTOR;
        size_t t = static_cast<size_t>(total);
        if (t >= MTU_LIMIT) {
            steps.push_back(MTU_LIMIT);
            break;
        }
        steps.push_back(t);
    }
    return steps;
}

/**
 * @brief Evaluates various flood payloads for a given target size to find the most potent mutation.
 * 
 * @param poc_packet Base POC exploit buffer.
 * @param target_total Desired total packet size in bytes.
 * @param exploit_header_size exploit header size threshold separating ASN.1 headers.
 * @param runs_per_size Count of benchmark runs to execute.
 * @param min_valid_runs Minimum count of valid runs required to accept a strategy.
 * @param max_attempts_factor Scaling factor limiting maximum trials.
 * @return ProbeResult containing the best strategy's performance telemetry.
 */
ProbeResult probeOneSize(const vanetza::ByteBuffer& poc_packet, size_t target_total, size_t exploit_header_size,
                         int runs_per_size, int min_valid_runs, int max_attempts_factor) {
    ProbeResult best = {0, 0, LLONG_MAX, 0, 0, 0, false, {}, 1, "flat-0x02 (Dense ASN.1 Recursion)", 1};
    if (target_total > MTU_LIMIT) return best;

    size_t flood_size = (target_total > exploit_header_size) ? target_total - exploit_header_size : 0;
    int total_attempts = 0, total_rejected = 0;

    auto strategies = TrafficGenerator::makeStrategies();
    vanetza::ByteBuffer flat02_flood;
    for (const auto& s : strategies) {
        if (s.first.find("flat-0x02") != std::string::npos) {
            flat02_flood = s.second(flood_size);
            break;
        }
    }

    vanetza::ByteBuffer test_pkt(exploit_header_size);
    std::copy(poc_packet.begin(), poc_packet.begin() + exploit_header_size, test_pkt.begin());
    test_pkt.insert(test_pkt.end(), flat02_flood.begin(), flat02_flood.end());

    std::vector<long long> samples;
    int valid = 0, crashed = 0;
    int max_attempts = runs_per_size * max_attempts_factor, attempts = 0;

    while (valid < runs_per_size && attempts < max_attempts) {
        attempts++;
        total_attempts++;
        long long lat = HarnessEngine::measurePacketLatency(test_pkt);
        if (lat > 0) {
            samples.push_back(lat);
            best.min_ns = std::min(best.min_ns, lat);
            best.max_ns = std::max(best.max_ns, lat);
            valid++;
        } else {
            crashed++;
            total_rejected++;
        }
        long long current_med = !samples.empty() ? samples[samples.size() / 2] : 0LL;
        
        if (valid % 100 == 0 || valid == runs_per_size) {
            ConsolePresenter::printProbeProgress(target_total, 1, 1, best.best_strategy_name, valid, crashed,
                                                 current_med);
        }
    }
    ConsolePresenter::clearLine();

    if (valid >= min_valid_runs) {
        std::sort(samples.begin(), samples.end());
        long long median = samples[samples.size() / 2];
        long long total_lat = 0;
        for (const long long s : samples) total_lat += s;
        long long avg = total_lat / valid;

        best.avg_ns = avg;
        best.median_ns = median;
        best.valid_runs = valid;
        best.crashed_runs = crashed;
        best.sufficient = true;
        best.best_packet = test_pkt;
        best.recursion_depth = static_cast<int>(flood_size / 2);
        
        double reject_rate = total_attempts > 0 ? 100.0 * total_rejected / total_attempts : 0.0;
        ConsolePresenter::printProbeResult(target_total, 0, best.best_strategy_name, reject_rate);
    }
    return best;
}
}  // namespace

/**
 * @brief Compares normal traffic vs. exploit packets and analyzes the workload contribution
 *        of mutated suffix structures.
 * 
 * @param poc_packet Base exploit packet buffer.
 */
void AmplificationProfiler::runFloodDiagnosis(const vanetza::ByteBuffer& poc_packet) {
    ConsolePresenter::printDiagnosisHeader();
    const int RUNS = 10000;
    double poc_vs_normal_ratio = 0.0;

    std::string normal_path = std::string(REPO_ROOT) + "/inputs/base_packets/cam_v3_certificate.dat";
    vanetza::ByteBuffer normal_pkt = FileManager::readFileIntoBuffer(normal_path);

    ConsolePresenter::printSectionHeader("  NORMAL vs POC BASELINE");
    long long bl_avg[2] = {0, 0};

    BaselineResult res_norm = measureRepeatedLatency(normal_pkt, RUNS, "NORMAL  cam_v3_certificate.dat");
    bl_avg[0] = res_norm.avg_ns;
    ConsolePresenter::printTimingRow("NORMAL  cam_v3_certificate.dat", res_norm.avg_ns, res_norm.min_ns,
                                     res_norm.max_ns, res_norm.valid_runs, RUNS);

    BaselineResult res_poc = measureRepeatedLatency(poc_packet, RUNS, "POC     poc_mtu_limit.bin");
    bl_avg[1] = res_poc.avg_ns;
    ConsolePresenter::printTimingRow("POC     poc_mtu_limit.bin", res_poc.avg_ns, res_poc.min_ns, res_poc.max_ns,
                                     res_poc.valid_runs, RUNS);

    if (bl_avg[0] > 0 && bl_avg[1] > 0) {
        poc_vs_normal_ratio = static_cast<double>(bl_avg[1]) / bl_avg[0];
        ConsolePresenter::printRatioRow("POC / NORMAL ratio:", poc_vs_normal_ratio);
    }

    // Build mutated test packets to isolate parsing bottlenecks
    vanetza::ByteBuffer var_02 = poc_packet;
    vanetza::ByteBuffer var_00 = poc_packet;
    for (size_t i = EXPLOIT_HEADER_SIZE; i < var_00.size(); ++i) {
        var_00[i] = 0x00;
    }
    vanetza::ByteBuffer var_hdr(poc_packet.begin(),
                                poc_packet.begin() + std::min(EXPLOIT_HEADER_SIZE, poc_packet.size()));
    vanetza::ByteBuffer var_min = var_hdr;
    var_min.push_back(0x02);

    vanetza::ByteBuffer const* variants[] = {&var_02, &var_00, &var_hdr, &var_min};
    const char* var_labels[] = {"A: original  (0x02 flood, 353B)", "B: zero flood (0x00 flood, 353B)",
                                "C: header only           (64B)", "D: header + 1 byte       (65B)"};
    long long results[4] = {0};

    ConsolePresenter::printSectionHeader("  MUTATED FLOOD VARIANTS COMPARISON");
    for (int v = 0; v < 4; ++v) {
        BaselineResult v_res = measureRepeatedLatency(*variants[v], RUNS, var_labels[v]);
        results[v] = v_res.avg_ns;
        ConsolePresenter::printVariantRow(var_labels[v], v_res.avg_ns, v_res.min_ns, v_res.max_ns, v_res.valid_runs,
                                          RUNS);
    }

    long long diff_02_vs_00 = results[0] - results[1];
    long long diff_02_vs_hdr = results[0] - results[2];
    double pct_flood_contrib = results[0] > 0 ? 100.0 * diff_02_vs_00 / results[0] : 0.0;

    ConsolePresenter::printInterpretation(diff_02_vs_00, pct_flood_contrib, diff_02_vs_hdr, poc_vs_normal_ratio);
    ConsolePresenter::printDiagnosisEndBox();
}

/**
 * @brief Automatically executes geometric packet size sweeps, generates target payloads,
 *        and logs processing metrics to a CSV profile.
 * 
 * @param poc_packet Base exploit packet buffer.
 */
void AmplificationProfiler::runAmplificationProfiling(const vanetza::ByteBuffer& poc_packet) {
    ConsolePresenter::printProfilerHeader();
    const int RUNS_PER_SIZE = 10000;
    const int MIN_VALID_RUNS = 5;
    const int MAX_ATTEMPTS_FACTOR = 5;

    size_t poc_flood_size = poc_packet.size() - EXPLOIT_HEADER_SIZE;

    ConsolePresenter::printSectionHeader("  TARGET PACKET ANATOMY");
    ConsolePresenter::printAnatomyBlock(poc_packet.size(), EXPLOIT_HEADER_SIZE, poc_flood_size);

    const std::string REPO_ROOT_STR = REPO_ROOT;
    std::string out_dir = REPO_ROOT_STR + "/outputs";
    std::string csv_dir = out_dir + "/csv_raw";
    std::string amp_dir = out_dir + "/amp_packets";

    mkdir(out_dir.c_str(), 0755);
    mkdir(csv_dir.c_str(), 0755);
    mkdir(amp_dir.c_str(), 0755);

    // Scan for existing profiling packets to enforce academic consistency
    std::vector<std::string> existing_files;
    DIR* pdir = opendir(amp_dir.c_str());
    if (pdir) {
        struct dirent* entry;
        while ((entry = readdir(pdir)) != nullptr) {
            std::string name = entry->d_name;
            if (name.rfind("amp_", 0) == 0 && name.size() >= 4 && name.compare(name.size() - 4, 4, ".bin") == 0) {
                existing_files.push_back(amp_dir + "/" + name);
            }
        }
        closedir(pdir);
    }
    std::sort(existing_files.begin(), existing_files.end());

    bool load_existing = false;
    if (!existing_files.empty()) {
        std::cout << "[?] Found " << existing_files.size() << " existing amp packets in outputs/amp_packets.\n";
        std::cout << "    Do you want to load them instead of re-probing? (y/n) [default: y]: ";
        std::string ans;
        std::getline(std::cin, ans);
        if (ans.empty() || ans[0] == 'y' || ans[0] == 'Y') {
            load_existing = true;
        }
    }

    std::ofstream csv(csv_dir + "/amplification_profile.csv");
    csv << "total_size_bytes,flood_size_bytes,median_latency_ns,mean_latency_ns,min_latency_ns,max_latency_ns,"
           "amp_vs_normal,valid_runs,crashed_runs,recursion_depth\n";

    std::string norm_path = REPO_ROOT_STR + "/inputs/base_packets/cam_v3_certificate.dat";
    vanetza::ByteBuffer normal_pkt = FileManager::readFileIntoBuffer(norm_path);

    ConsolePresenter::printSectionHeader("  NORMAL PACKET BASELINE");
    BaselineResult norm = measureRepeatedLatency(normal_pkt, RUNS_PER_SIZE, "baseline");
    BaselineResult poc = measureRepeatedLatency(poc_packet, RUNS_PER_SIZE, "baseline");

    double base_ratio = static_cast<double>(poc.median_ns) / norm.median_ns;
    ConsolePresenter::printBaselineSummary(normal_pkt.size(), norm.median_ns, norm.avg_ns, norm.min_ns, norm.max_ns,
                                           norm.valid_runs, poc_packet.size(), poc.median_ns, poc.avg_ns, poc.min_ns,
                                           poc.max_ns, poc.valid_runs, base_ratio, RUNS_PER_SIZE);

    csv << "# normal_baseline," << normal_pkt.size() << "," << norm.median_ns << "," << norm.avg_ns << ","
        << norm.min_ns << "," << norm.max_ns << "\n";
    csv << "# poc_baseline," << poc_packet.size() << "," << poc.median_ns << "," << poc.avg_ns << "," << poc.min_ns
        << "," << poc.max_ns << "\n";
    csv << "# poc_vs_normal_ratio_median," << base_ratio << "\n";

    ConsolePresenter::printHorizontalSeparator();
    double last_median = 0.0;

    if (load_existing) {
        std::cout << "[*] Loading existing amp packets for evaluation...\n";
        ConsolePresenter::printTableHeader();
        for (const auto& fpath : existing_files) {
            vanetza::ByteBuffer loaded_pkt = FileManager::readFileIntoBuffer(fpath);
            if (loaded_pkt.empty()) continue;

            size_t target_total = loaded_pkt.size();
            size_t flood_size = (target_total > EXPLOIT_HEADER_SIZE) ? target_total - EXPLOIT_HEADER_SIZE : 0;

            int parsed_depth = 1;
            size_t depth_pos = fpath.find("_depth");
            if (depth_pos != std::string::npos && depth_pos + 6 < fpath.size()) {
                parsed_depth = std::atoi(fpath.c_str() + depth_pos + 6);
            }

            BaselineResult pr;
            int retries = 0;
            const int MAX_RETRIES = 3;
            while (retries <= MAX_RETRIES) {
                pr = measureRepeatedLatency(loaded_pkt, RUNS_PER_SIZE, "loaded  ");
                if (last_median > 0 && pr.median_ns < last_median && retries < MAX_RETRIES) {
                    retries++;
                    std::cout << "\n[!] Warning: Loaded size [" << target_total << " B] median latency ("
                              << pr.median_ns << " ns) is faster than previous (" << last_median
                              << " ns). Retrying timing (" << retries << "/" << MAX_RETRIES << ")..." << std::endl;
                    continue;
                }
                break;
            }
            last_median = pr.median_ns;

            int actual_depth = parsed_depth;
            if (pr.crashed_runs > 0 || pr.valid_runs < MIN_VALID_RUNS) {
                actual_depth = 1;
            }

            double amp = static_cast<double>(pr.median_ns) / norm.median_ns;
            double flood_mult = poc_flood_size > 0 ? static_cast<double>(flood_size) / poc_flood_size : 0.0;

            ConsolePresenter::printProgressionRow(target_total, flood_size, flood_mult, pr.median_ns, pr.avg_ns, pr.min_ns,
                                                  pr.max_ns, amp, pr.valid_runs, RUNS_PER_SIZE);
            if (actual_depth > 1) {
                std::printf("   └─> [CWE-674 Recursion Depth: %d]\n", actual_depth);
            } else {
                std::printf("   └─> [CWE-674 Recursion Depth: %d (Blocked/Non-recursive)]\n", actual_depth);
            }

            csv << target_total << "," << flood_size << "," << pr.median_ns << "," << pr.avg_ns << "," << pr.min_ns << ","
                << pr.max_ns << "," << amp << "," << pr.valid_runs << "," << pr.crashed_runs << "," << actual_depth << "\n";
        }
    } else {
        std::vector<size_t> target_sizes = buildSizeSteps(poc_packet.size());
        ConsolePresenter::printSizeProgressionHeader(target_sizes.size(), SIZE_STEP_FACTOR, target_sizes);
        ConsolePresenter::printTableHeader();

        int file_idx = 0;
        for (size_t target_total : target_sizes) {
            size_t flood_size = (target_total > EXPLOIT_HEADER_SIZE) ? target_total - EXPLOIT_HEADER_SIZE : 0;
            
            ProbeResult pr;
            int retries = 0;
            const int MAX_RETRIES = 3;
            while (retries <= MAX_RETRIES) {
                pr = probeOneSize(poc_packet, target_total, EXPLOIT_HEADER_SIZE, RUNS_PER_SIZE, MIN_VALID_RUNS,
                                  MAX_ATTEMPTS_FACTOR);
                if (pr.sufficient && last_median > 0 && pr.median_ns < last_median && retries < MAX_RETRIES) {
                    retries++;
                    std::cout << "\n[!] Warning: Probed size [" << target_total << " B] median latency ("
                              << pr.median_ns << " ns) is faster than previous (" << last_median
                              << " ns). Retrying sweep (" << retries << "/" << MAX_RETRIES << ")..." << std::endl;
                    continue;
                }
                break;
            }

            if (!pr.sufficient) {
                ConsolePresenter::printSkipRow(target_total, flood_size, pr.valid_runs, RUNS_PER_SIZE);
                csv << target_total << "," << flood_size << ",INSUFFICIENT,,,," << pr.valid_runs << "," << pr.crashed_runs << ",0\n";
                continue;
            }

            last_median = pr.median_ns;

            double amp = static_cast<double>(pr.median_ns) / norm.median_ns;
            double flood_mult = poc_flood_size > 0 ? static_cast<double>(flood_size) / poc_flood_size : 0.0;

            char amp_path[256];
            std::snprintf(amp_path, sizeof(amp_path), "%s/amp_%05d_size%05zu_depth%02d.bin", amp_dir.c_str(), file_idx++,
                          target_total, pr.recursion_depth);
            FileManager::writeBufferToFile(amp_path, pr.best_packet);

            ConsolePresenter::printProgressionRow(target_total, flood_size, flood_mult, pr.median_ns, pr.avg_ns, pr.min_ns,
                                                  pr.max_ns, amp, pr.valid_runs, RUNS_PER_SIZE);
            if (pr.recursion_depth > 1) {
                std::printf("   └─> [CWE-674 Recursion Depth: %d]\n", pr.recursion_depth);
            } else {
                std::printf("   └─> [CWE-674 Recursion Depth: %d (Blocked/Non-recursive)]\n", pr.recursion_depth);
            }

            csv << target_total << "," << flood_size << "," << pr.median_ns << "," << pr.avg_ns << "," << pr.min_ns << ","
                << pr.max_ns << "," << amp << "," << pr.valid_runs << "," << pr.crashed_runs << "," << pr.recursion_depth << "\n";
        }
    }
    csv.close();

    ConsolePresenter::printProfilerEndBox(MTU_LIMIT, "outputs/csv_raw/amplification_profile.csv",
                                          "outputs/amp_packets/amp_NNNNN_sizeNNNNN_depthNN.bin");
}

}  // namespace qos_harness