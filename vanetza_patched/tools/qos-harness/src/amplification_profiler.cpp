#include "qos_harness/amplification_profiler.hpp"

#include <sys/stat.h>

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
struct BaselineResult {
    long long avg_ns;
    long long median_ns;
    long long min_ns;
    long long max_ns;
    int valid_runs;
    int crashed_runs;
};

struct ProbeResult {
    long long avg_ns;
    long long median_ns;
    long long min_ns;
    long long max_ns;
    int valid_runs;
    int crashed_runs;
    bool sufficient;
};

const size_t MTU_LIMIT = 1400;
const double SIZE_STEP_FACTOR = 1.10;
const size_t EXPLOIT_HEADER_SIZE = 64;

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

    if (samples.empty()) return r;
    long long total = 0;
    for (const long long s : samples) total += s;
    r.avg_ns = total / (long long)samples.size();

    std::sort(samples.begin(), samples.end());
    r.median_ns = samples[samples.size() / 2];
    return r;
}

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

ProbeResult probeOneSize(const vanetza::ByteBuffer& poc_packet, size_t target_total, size_t exploit_header_size,
                         int runs_per_size, int min_valid_runs, int max_attempts_factor) {
    ProbeResult best = {0, 0, LLONG_MAX, 0, 0, 0, false};
    int best_strategy_idx = -1;
    if (target_total > MTU_LIMIT) return best;

    size_t flood_size = (target_total > exploit_header_size) ? target_total - exploit_header_size : 0;
    auto strategies = TrafficGenerator::makeStrategies();
    int total_attempts = 0, total_rejected = 0;

    for (int si = 0; si < (int)strategies.size(); si++) {
        const auto& [name, fn] = strategies[si];
        vanetza::ByteBuffer test_pkt(exploit_header_size);
        std::copy(poc_packet.begin(), poc_packet.begin() + exploit_header_size, test_pkt.begin());
        vanetza::ByteBuffer flood = fn(flood_size);
        test_pkt.insert(test_pkt.end(), flood.begin(), flood.end());

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
            ConsolePresenter::printProbeProgress(target_total, si + 1, (int)strategies.size(), name, valid, crashed,
                                                 current_med);
        }

        if (valid < min_valid_runs) {
            total_rejected += valid;
            continue;
        }
        std::sort(samples.begin(), samples.end());
        long long median = samples[samples.size() / 2];
        long long total_lat = 0;
        for (const long long s : samples) total_lat += s;
        long long avg = total_lat / valid;

        if (!best.sufficient || median > best.median_ns) {
            best.avg_ns = avg;
            best.median_ns = median;
            best.valid_runs = valid;
            best.crashed_runs = crashed;
            best.sufficient = true;
            best_strategy_idx = si;
        }
    }
    ConsolePresenter::clearLine();

    if (best.sufficient) {
        double reject_rate = total_attempts > 0 ? 100.0 * total_rejected / total_attempts : 0.0;
        ConsolePresenter::printProbeResult(target_total, best_strategy_idx, strategies[best_strategy_idx].first,
                                           reject_rate);
    }
    return best;
}
}  // namespace

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

    std::ofstream csv(csv_dir + "/amplification_profile.csv");
    csv << "total_size_bytes,flood_size_bytes,median_latency_ns,mean_latency_ns,min_latency_ns,max_latency_ns,"
           "amp_vs_normal,valid_runs,crashed_runs\n";

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

    std::vector<size_t> target_sizes = buildSizeSteps(poc_packet.size());
    ConsolePresenter::printSizeProgressionHeader(target_sizes.size(), SIZE_STEP_FACTOR, target_sizes);
    ConsolePresenter::printTableHeader();

    int file_idx = 0;
    for (size_t target_total : target_sizes) {
        size_t flood_size = (target_total > EXPLOIT_HEADER_SIZE) ? target_total - EXPLOIT_HEADER_SIZE : 0;
        ProbeResult pr = probeOneSize(poc_packet, target_total, EXPLOIT_HEADER_SIZE, RUNS_PER_SIZE, MIN_VALID_RUNS,
                                      MAX_ATTEMPTS_FACTOR);

        if (!pr.sufficient) {
            ConsolePresenter::printSkipRow(target_total, flood_size, pr.valid_runs, RUNS_PER_SIZE);
            csv << target_total << "," << flood_size << ",INSUFFICIENT,,,," << pr.valid_runs << "," << pr.crashed_runs
                << "\n";
            continue;
        }

        double amp = static_cast<double>(pr.median_ns) / norm.median_ns;
        double flood_mult = poc_flood_size > 0 ? static_cast<double>(flood_size) / poc_flood_size : 0.0;

        vanetza::ByteBuffer save_pkt(EXPLOIT_HEADER_SIZE);
        std::copy(poc_packet.begin(), poc_packet.begin() + EXPLOIT_HEADER_SIZE, save_pkt.begin());
        save_pkt.resize(EXPLOIT_HEADER_SIZE + flood_size, 0x02);

        char amp_path[256];
        std::snprintf(amp_path, sizeof(amp_path), "%s/amp_%05d_size%05zu.bin", amp_dir.c_str(), file_idx++,
                      target_total);
        FileManager::writeBufferToFile(amp_path, save_pkt);

        ConsolePresenter::printProgressionRow(target_total, flood_size, flood_mult, pr.median_ns, pr.avg_ns, pr.min_ns,
                                              pr.max_ns, amp, pr.valid_runs, RUNS_PER_SIZE);

        csv << target_total << "," << flood_size << "," << pr.median_ns << "," << pr.avg_ns << "," << pr.min_ns << ","
            << pr.max_ns << "," << amp << "," << pr.valid_runs << "," << pr.crashed_runs << "\n";
    }
    csv.close();

    ConsolePresenter::printProfilerEndBox(MTU_LIMIT, "outputs/csv_raw/amplification_profile.csv",
                                          "outputs/amp_packets/amp_NNNNN_sizeNNNNN.bin");
}

}  // namespace qos_harness