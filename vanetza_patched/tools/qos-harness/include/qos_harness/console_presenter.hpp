#ifndef QOS_HARNESS_CONSOLE_PRESENTER_HPP
#define QOS_HARNESS_CONSOLE_PRESENTER_HPP

#include <string>
#include <vector>
#include <cstdint>

namespace qos_harness {

struct OnnxAsyncDiagnostics {
    uint64_t windows_published = 0;
    uint64_t telemetry_consumed = 0;
    uint64_t telemetry_overwritten = 0;
    uint64_t inferences_completed = 0;
    uint64_t policies_applied = 0;
    uint64_t policies_superseded = 0;
    uint64_t policies_unchanged = 0;
    uint64_t policy_age_sum = 0;
    uint64_t policy_age_max = 0;
    uint64_t policy_age_over_one = 0;
    uint64_t inference_wall_total_us = 0;
    uint64_t inference_wall_p99_us = 0;
    uint64_t inference_cpu_total_us = 0;
    uint64_t publish_wall_total_us = 0;
    uint64_t mutex_wait_total_us = 0;
    uint64_t mutex_wait_max_us = 0;
};

class ConsolePresenter {
public:
    // Mapped color channels retained for main.cpp legacy compatibility
    static std::string reset();
    static std::string green();
    static std::string red();
    static std::string yellow();
    static std::string blue();

    // Standardized UNIX telemetry semantic palette definitions
    static std::string frame();
    static std::string info();
    static std::string safe();
    static std::string warn();
    static std::string crit();
    static std::string data();
    static std::string label();

    // High-visibility structural telemetry headers
    static void printDiagnosisHeader();
    static void printProfilerHeader();
    static void printSectionHeader(const std::string& title);
    static void printHorizontalSeparator();

    // Dedicated UDP Testbed Hardware Presentation Interface
    static void printUDPReceiverDaemonBanner(int port, const std::string& build_type);
    static void printUDPSessionHeader(int mode, double rate, int total_pkts, double lambda_pps, uint32_t filter_mode);
    static void printUDPSenderBanner(const std::string& dest_ip, int port, size_t modes_cnt, size_t rates_cnt);

    // Real-time loop progression telemetry trackers
    static void printBaselineProgress(const std::string& label, int run, int total, int ok, int crash, long long last);
    static void printVariantProgress(const std::string& label, int run, int total, int ok, int crash, long long last);
    static void printProbeProgress(size_t size, int idx, int count, const std::string& name, int ok, int rj,
                                   long long med);
    static void printDatasetProgress(int gen, int target, int rj, long long lat);
    static void printDatasetHeader(long long normal_lat, long long base_poc_lat);
    static void printHillClimbStep(int generated, int target, int attempt, int gen, int total_gens, 
                                   long long parent_lat, long long mutant_lat, long long normal_lat, 
                                   int rejects);
    static void printDatasetCompleteSummary(int generated, int total_attempts, int rejects, double avg_lat, double normal_lat);
    static void printSimulationProgress(int current, int total, int malware, 
                                        bool enable_filter = false, 
                                        double actual_rate = 0.0, 
                                        double target_rate = 0.0);

    // Hardware-level terminal carriage eraser
    static void clearLine();

    // Matrix and telemetry statistical data blocks
    static void printTimingRow(const std::string& label, long long avg, long long min, long long max, int ok,
                               int total);
    static void printVariantRow(const std::string& label, long long avg, long long min, long long max, int ok,
                                int total);
    static void printRatioRow(const std::string& label, double ratio);
    static void printAnatomyBlock(size_t total_size, size_t header_size, size_t flood_size);
    static void printBaselineSummary(size_t n_size, long long n_med, long long n_avg, long long n_min, long long n_max,
                                     int n_ok, size_t p_size, long long p_med, long long p_avg, long long p_min,
                                     long long p_max, int p_ok, double ratio, int runs);
    static void printSizeProgressionHeader(size_t steps, double factor, const std::vector<size_t>& sizes);
    static void printTableHeader();
    static void printProgressionRow(size_t size, size_t flood, double mult, long long med, long long avg, long long min,
                                    long long max, double amp, int ok, int total);
    static void printSkipRow(size_t size, size_t flood, int ok, int total);
    static void printProbeResult(size_t target_total, int strategy_idx, const std::string& name, double reject_rate);

    // Hardcoded academic verbatim analysis output sections
    static void printInterpretation(long long diff_ab, double pct, long long diff_ac, double ratio);
    static void printDiagnosisEndBox();
    static void printProfilerEndBox(size_t limit, const std::string& csv, const std::string& bin);
    static void printSecurityReport(int total, int malware, int tp, int tn, int fp, int fn);
    static void printAblationMetrics(const std::string& config_name, double fnr, double avg_sampling, const std::string& cost_str);
    static void printOnnxAsyncDiagnostics(const OnnxAsyncDiagnostics& report);
};

}  // namespace qos_harness

#endif  // QOS_HARNESS_CONSOLE_PRESENTER_HPP
