/**
 * @file console_presenter.cpp
 * @brief Implementation of terminal visualizer helpers and formatted progress bars.
 * 
 * DESIGN CONTEXT & UI FORMATTING:
 * This helper class centralizes terminal display logic. It manages ANSI escape 
 * codes for color-coded status reporting (green/yellow/red/blue) and prints formatted 
 * tables, progression rows, progress bars, and security evaluation reports.
 */

#include "qos_harness/console_presenter.hpp"

#include <cmath>
#include <cstdio>
#include <iostream>
#include <vector>

namespace qos_harness {

// Static functions providing ANSI escape codes for terminal coloring
std::string ConsolePresenter::reset() { return "\033[0m"; }
std::string ConsolePresenter::green() { return safe(); }
std::string ConsolePresenter::red() { return crit(); }
std::string ConsolePresenter::yellow() { return warn(); }
std::string ConsolePresenter::blue() { return info(); }
std::string ConsolePresenter::frame() { return "\033[90m"; } // Gray line border
std::string ConsolePresenter::info() { return "\033[36m";  } // Cyan
std::string ConsolePresenter::safe() { return "\033[32m";  } // Green
std::string ConsolePresenter::warn() { return "\033[33m";  } // Yellow
std::string ConsolePresenter::crit() { return "\033[1;31m"; } // Bold Red
std::string ConsolePresenter::data() { return "\033[37m";  } // White
std::string ConsolePresenter::label() { return "\033[1;34m"; } // Bold Blue

/**
 * @brief Prints diagnosis banner for ASN.1 payload mutator.
 */
void ConsolePresenter::printDiagnosisHeader() {
    std::printf(
        "\n%s┌──────────────────────────────────────────────────────────────┐\n"
        "│%s                VANETZA SYSTEM: FLOOD REGION DIAGNOSIS        %s│\n"
        "└──────────────────────────────────────────────────────────────┘%s\n\n",
        frame().c_str(), label().c_str(), frame().c_str(), reset().c_str());
}

/**
 * @brief Prints telemetry sweep initialization header.
 */
void ConsolePresenter::printProfilerHeader() {
    std::printf(
        "\n%s┌─────────────────────────────────────────────────────────────────────────────────┐\n"
        "│%s                   VANETZA SYSTEM: MTU AMPLIFICATION PROFILER                    %s│\n"
        "└─────────────────────────────────────────────────────────────────────────────────┘%s\n\n",
        frame().c_str(), label().c_str(), frame().c_str(), reset().c_str());
}

/**
 * @brief Prints a standardized section title.
 * 
 * @param title Section header name.
 */
void ConsolePresenter::printSectionHeader(const std::string& title) {
    std::printf("%s:: %s%s\n", info().c_str(), title.c_str(), reset().c_str());
}

/**
 * @brief Prints a horizontal partition line.
 */
void ConsolePresenter::printHorizontalSeparator() {
    std::printf("  %s──────────────────────────────────────────────────────────────%s\n\n", frame().c_str(),
                reset().c_str());
}

/**
 * @brief Prints active baseline latency test progress.
 */
void ConsolePresenter::printBaselineProgress(const std::string& label_str, int run, int total, int ok, int crash,
                                             long long last) {
    std::printf("\r  %s[%-32s]%s  run %5d/%d  %sok=%-5d%s  %scrash=%-3d%s  last=%8lld ns", info().c_str(),
                label_str.c_str(), reset().c_str(), run, total, safe().c_str(), ok, reset().c_str(), crit().c_str(),
                crash, reset().c_str(), last);
    std::fflush(stdout);
}

/**
 * @brief Prints mutated variant baseline progress.
 */
void ConsolePresenter::printVariantProgress(const std::string& label_str, int run, int total, int ok, int crash,
                                            long long last) {
    std::printf("\r  %s[%-32s]%s  run %2d/%d  %sok=%-2d%s  %scrash=%-2d%s  last=%7lld ns", warn().c_str(),
                label_str.c_str(), reset().c_str(), run, total, safe().c_str(), ok, reset().c_str(), crit().c_str(),
                crash, reset().c_str(), last);
    std::fflush(stdout);
}

/**
 * @brief Prints the progress of testing a specific payload size.
 */
void ConsolePresenter::printProbeProgress(size_t size, int idx, int count, const std::string& name, int ok, int rj,
                                          long long med) {
    std::printf("\r  %s[%4zu B | strategy %d/%-d | %-28s]%s  ok=%-2d  reject=%-2d  med=%7lld ns", warn().c_str(), size,
                idx, count, name.c_str(), reset().c_str(), ok, rj, med);
    std::fflush(stdout);
}

/**
 * @brief Prints offline training dataset generation progress.
 */
void ConsolePresenter::printDatasetProgress(int gen, int target, int rj, long long lat) {
    std::printf("\r  %s[+] Dataset Collection Status:%s  %4d/%-4d  |  %sRejected: %-6d%s  |  Lat: %lld ns\033[K",
                safe().c_str(), reset().c_str(), gen, target, crit().c_str(), rj, reset().c_str(), lat);
    std::fflush(stdout);
}

/**
 * @brief Prints progress details of active simulation sequences.
 */
void ConsolePresenter::printSimulationProgress(int current, int total, int malware, 
                                               bool enable_filter, double actual_rate, double target_rate) {
    // Appended ANSI clear sequence to vaporize any unexpected trailing shell prompt ghosts
    std::printf("\r  %s[*] Loop:%s %7d/%7d | %sMal: %-5d%s | %5.1f%%",
                info().c_str(), reset().c_str(), current, total, 
                crit().c_str(), malware, reset().c_str(), 
                100.0 * current / total);

    // If the filter is enabled, monitoring metrics from RL and FSM are dynamically concatenated.
    // A = Actual (the proportion of actual F2 Sketch execution)
    // T = Target (the target sampling rate currently determined by the FSM)
    if (enable_filter && current > 0) {
        std::printf(" | %sInsp[A/T]:%s %6.2f%% / %6.2f%%", 
                    warn().c_str(), reset().c_str(), actual_rate, target_rate);
    }

    std::printf("\033[K");

    // Inject explicit line feed on termination frame to release carriage return scrollback lock
    if (current >= total - 1) {
        std::printf("\n");
    }
    std::fflush(stdout);
}

/**
 * @brief Clears the current line on standard output using carriage return escape sequences.
 */
void ConsolePresenter::clearLine() {
    std::printf("\r\033[K");
    std::fflush(stdout);
}

/**
 * @brief Prints a row displaying timing information.
 */
void ConsolePresenter::printTimingRow(const std::string& label_str, long long avg, long long min, long long max, int ok,
                                      int total) {
    std::printf("\r\033[K");
    std::printf("  %-44s  %savg=%8lld ns%s  min=%8lld ns  max=%8lld ns  valid=%d/%d\n", label_str.c_str(),
                data().c_str(), avg, reset().c_str(), min, max, ok, total);
}

/**
 * @brief Prints a row displaying variant benchmarks.
 */
void ConsolePresenter::printVariantRow(const std::string& label_str, long long avg, long long min, long long max,
                                       int ok, int total) {
    std::printf("\r\033[K");
    std::printf("  %s%-42s%s  avg=%8lld ns  min=%8lld ns  max=%8lld ns  valid=%d/%d\n", info().c_str(),
                label_str.c_str(), reset().c_str(), avg, min, max, ok, total);
}

/**
 * @brief Displays the latency ratio between exploit and normal baseline packets.
 */
void ConsolePresenter::printRatioRow(const std::string& label_str, double ratio) {
    std::string color = (ratio < 2.0) ? safe() : (ratio < 10.0) ? warn() : crit();
    std::printf("  %-44s  %sx%.2f%s  (Telemetry matrix amplification scale)\n\n", label_str.c_str(), color.c_str(),
                ratio, reset().c_str());
    if (ratio < 2.0) {
        std::printf(
            "  %s[SYSTEM NOTICE] POC/Normal ratio < 2.0 — mitigation state active at this footprint.%s\n"
            "  Recursive core tracking bypassed automatically.\n\n",
            safe().c_str(), reset().c_str());
    }
}

/**
 * @brief Prints structural size details and the threat classification vector.
 */
void ConsolePresenter::printAnatomyBlock(size_t total_size, size_t header_size, size_t flood_size) {
    std::printf("  %-28s %zu bytes\n", "Target binary payload:", total_size);
    std::printf("  %-28s bytes[0-%zu] (read-only baseline descriptor)\n", "Exploit tracking header:", header_size - 1);
    std::printf("  %-28s %zu bytes\n", "Fuzz mutation flood zone:", flood_size);
    std::printf("  %-28s CWE-674 Unbounded Recursion via Stack Exhaustion\n\n", "Core Threat Vector:");
}

/**
 * @brief Prints baseline execution performance parameters for the profiler.
 */
void ConsolePresenter::printBaselineSummary(size_t n_size, long long n_med, long long n_avg, long long n_min,
                                             long long n_max, int n_ok, size_t p_size, long long p_med, long long p_avg,
                                             long long p_min, long long p_max, int p_ok, double ratio, int runs) {
    std::printf("  %-28s %zu bytes\n", "Legitimate CAM frame footprint:", n_size);
    std::printf("  %-28s median=%-9lld  mean=%-9lld  min=%-9lld  max=%-9lld  valid=%d/%d\n",
                "Baseline latency response:", n_med, n_avg, n_min, n_max, n_ok, runs);
    std::printf("  %-28s %zu bytes\n", "Attack vector trigger frame:", p_size);
    std::printf("  %-28s median=%-9lld  mean=%-9lld  min=%-9lld  max=%-9lld  valid=%d/%d\n",
                "Exploit latency response:", p_med, p_avg, p_min, p_max, p_ok, runs);
    std::string color = (ratio < 10.0) ? safe() : (ratio < 50.0) ? warn() : crit();
    std::printf("  %-28s %sx%.2f%s  (Mathematical multiplier factor comparison metrics)\n\n",
                "CPU Degradation Ratio:", color.c_str(), ratio, reset().c_str());
}

/**
 * @brief Prints the geometric size progressions.
 */
void ConsolePresenter::printSizeProgressionHeader(size_t steps, double factor, const std::vector<size_t>& sizes) {
    std::printf("  GEOMETRIC SWEEP PROGRESSION  (%zu distinct intervals, x%.2f geometric factor multiplier)\n  %s",
                steps, factor, frame().c_str());
    for (size_t s : sizes) std::printf("%zu ", s);
    std::printf("%s\n\n", reset().c_str());
}

/**
 * @brief Prints table titles for the size progression matrix.
 */
void ConsolePresenter::printTableHeader() {
    std::printf("%s  %-8s  %-8s  %-8s  %-12s  %-12s  %-12s  %-12s  %-8s  %-6s%s\n", label().c_str(), "SIZE(B)",
                "FLOOD(B)", "FLOOD-Mx", "MEDIAN(ns)", "MEAN(ns)", "MIN(ns)", "MAX(ns)", "AMP-Mx", "VALID",
                reset().c_str());
    std::printf("  %s%-8s  %-8s  %-8s  %-12s  %-12s  %-12s  %-12s  %-8s  %-6s%s\n", frame().c_str(), "--------",
                "--------", "--------", "------------", "------------", "------------", "------------", "--------",
                "------", reset().c_str());
}

/**
 * @brief Prints a table row containing benchmark statistics.
 */
void ConsolePresenter::printProgressionRow(size_t size, size_t flood, double mult, long long med, long long avg,
                                            long long min, long long max, double amp, int ok, int total) {
    std::printf("\r\033[K");
    std::string color = (amp < 5.0) ? safe() : (amp < 15.0) ? warn() : crit();
    std::printf("  %-8zu  %-8zu  x%-7.2f  %-12lld  %-12lld  %-12lld  %-12lld  %sx%-7.2f%s  %2d/%-4d\n", size, flood,
                mult, med, avg, min, max, color.c_str(), amp, reset().c_str(), ok, total);
}

/**
 * @brief Prints a row representing skipped sizes.
 */
void ConsolePresenter::printSkipRow(size_t size, size_t flood, int ok, int total) {
    std::printf("\r\033[K");
    std::printf("  %s%-8zu  %-8zu  %-8s  %-12s  %-12s  %-12s  %-8s  %2d/%-4d  CRITICAL SKIP%s\n", crit().c_str(), size,
                flood, "-", "-", "-", "-", "-", ok, total, reset().c_str());
}

/**
 * @brief Prints strategy selection details.
 */
void ConsolePresenter::printProbeResult(size_t target_total, int strategy_idx, const std::string& name,
                                         double reject_rate) {
    std::printf(
        "  %s├─%s Size [%4zu B] optimal kernel footprint selected: %sstrategy-%d (%s)%s  (reject-rate: %.1f%%)\n",
        frame().c_str(), reset().c_str(), target_total, warn().c_str(), strategy_idx + 1, name.c_str(), reset().c_str(),
        reject_rate);
}

/**
 * @brief Analyzes latency values and prints diagnostic conclusions.
 */
void ConsolePresenter::printInterpretation(long long diff_ab, double pct, long long diff_ac, double ratio) {
    std::printf("  %-44s  avg=0 ns  min=0 ns  max=0 ns  valid=0/0\n\n", "NORMAL  cam_v3_certificate.dat");
    std::printf("%s[ EXPERIMENTAL SYSTEM DECODE CONCLUSION ]%s\n", label().c_str(), reset().c_str());
    std::printf(
        "  ├── Divergence A vs B (0x02 vs 0x00 flood region)  : %+lld ns  (%.1f%% total core footprint contribution)\n",
        diff_ab, pct);
    std::printf("  └── Divergence A vs C (Full payload vs Header-only): %+lld ns\n", diff_ac);

    if (ratio > 0.0 && ratio < 2.0) {
        std::printf(
            "\n  %s[EVAL] SECURITY CONTROL ACTIVE — Structural recursion halted via early escape path.%s\n"
            "  Immutability Delta within noise threshold. Evaluation cycle safe from resource denial.\n",
            safe().c_str(), reset().c_str());
    } else if (pct < 5.0) {
        std::printf(
            "\n  %s[EVAL] RECURSION CONFIRMED — Degradation fully driven by top-level ASN.1 Header descriptor.%s\n"
            "  Fuzz flood region content operates as passive tracking volume. Execution vectors confirmed constant.\n",
            crit().c_str(), reset().c_str());
    } else if (diff_ab > 0) {
        std::printf(
            "\n  %s[EVAL] RECURSION CONFIRMED — Parser vulnerability actively parses and sweeps down entire flood "
            "map.%s\n"
            "  CPU depletion factor scales with packet length. Geometric progression matrix is scientifically valid.\n",
            safe().c_str(), reset().c_str());
    } else {
        std::printf(
            "\n  %s[EVAL] RECURSION CONFIRMED — Muted null field configurations demand excess evaluation cycles.%s\n"
            "  Parser pipeline optimization anomaly confirmed. Both mutation branches remain highly lethal.\n",
            warn().c_str(), reset().c_str());
    }
}

/**
 * @brief Prints the completion footer for payload diagnosis runs.
 */
void ConsolePresenter::printDiagnosisEndBox() {
    std::printf(
        "\n%s┌──────────────────────────────────────────────────────────────┐\n"
        "│%s  SYSTEM STATE STEADY: Execute --profile-amp for next matrix. %s│\n"
        "└──────────────────────────────────────────────────────────────┘%s\n\n",
        frame().c_str(), safe().c_str(), frame().c_str(), reset().c_str());
}

/**
 * @brief Prints the profiling summary footer.
 */
void ConsolePresenter::printProfilerEndBox(size_t limit, const std::string& csv, const std::string& bin) {
    std::printf(
        "\n%s┌─────────────────────────────────────────────────────────────────────────────────┐\n"
        "│ %sTELEMETRY COLLECTION COMPLETE%s                                                   │\n"
        "│ ├── Operation Scope Limit : <= %4zu Bytes (ITS MTU Threshold)                   │\n"
        "│ ├── Target Output Records : %-51s │\n"
        "│ └── Extracted Binary Maps : %-51s │\n"
        "└─────────────────────────────────────────────────────────────────────────────────┘%s\n\n",
        frame().c_str(), safe().c_str(), frame().c_str(), limit, csv.c_str(), bin.c_str(), reset().c_str());
}

/**
 * @brief Prints FSM security and packet routing validation reports.
 */
void ConsolePresenter::printSecurityReport(int total, int malware, int tp, int tn, int fp, int fn) {
    double total_attacks = tp + fn;
    double total_normal = tn + fp;

    std::printf(
        "\n%s┌──────────────────────────────────────────────────────────────┐\n"
        "│               AdaptiveFilterFSM SECURITY MONITOR REPORT      │\n"
        "└──────────────────────────────────────────────────────────────┘%s\n",
        frame().c_str(), reset().c_str());
    std::printf("  ├── Total Traffic Audited    : %d frames\n", total);
    std::printf("  ├── Exploit Injections Found : %d vectors\n", malware);
    std::printf("  ├── %sTrue Positives (Blocked) : %-6d (Control Secure)%s\n", safe().c_str(), tp, reset().c_str());
    std::printf("  ├── %sTrue Negatives (Passed)  : %-6d (Nominal Safe)%s\n", safe().c_str(), tn, reset().c_str());
    std::printf("  ├── %sFalse Positives (SelfDoS): %-6d (Service Disruption)%s\n", crit().c_str(), fp,
                reset().c_str());
    std::printf("  └── %sFalse Negatives (Missed) : %-6d (Latency Overflow Risk)%s\n", crit().c_str(), fn,
                reset().c_str());

    if (total_normal > 0)
        std::printf("  %s├── False Positive Rate (FPR) : %.2f%%%s\n", frame().c_str(), (fp / total_normal) * 100.0,
                    reset().c_str());
    if (total_attacks > 0)
        std::cout << "  " << frame() << "└── False Negative Rate (FNR) : " << (fn / total_attacks) * 100.0 << "%\n"
                  << reset();
    std::printf("  %s──────────────────────────────────────────────────────────────%s\n\n", frame().c_str(),
                reset().c_str());
}

}  // namespace qos_harness