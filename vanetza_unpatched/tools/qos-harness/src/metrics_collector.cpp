/**
 * @file metrics_collector.cpp
 * @brief Implementation of the telemetry data logging and validation reporting engine.
 * 
 * DESIGN CONTEXT & SAFETY ASSURANCE:
 * This class collects evaluation metrics across packet simulation sequences.
 * It logs classifications (TP/FP/TN/FN) and latency indicators, exports final logs 
 * to formatted CSV files, and prints security metrics (FPR / FNR) for performance tracking.
 */

#include "qos_harness/metrics_collector.hpp"
#include <iostream>
#include <fstream>
#include <iostream>

namespace qos_harness {

// Localized ANSI escape codes for clean terminal output formatting
namespace {
    const std::string RESET  = "\033[0m";
    const std::string GREEN  = "\033[32m";
    const std::string RED    = "\033[31m";
}

MetricsCollector::MetricsCollector()
    : true_positives_(0), false_positives_(0), true_negatives_(0), false_negatives_(0) {}

/**
 * @brief Reserves memory buffer capacity for log entries to prevent runtime allocations.
 * 
 * @param total_packets Desired capacity size.
 */
void MetricsCollector::reserve(size_t total_packets) {
    logs_.reserve(total_packets);
}

/**
 * @brief Logs packet outcomes and aggregates classification confusion matrix metrics.
 * 
 * @param id Sequential index of the packet.
 * @param is_malware True if the payload contains exploit mutations.
 * @param was_dropped True if the FSM pre-filter blocked the packet.
 * @param latency_ns Parsing duration benchmark value in nanoseconds.
 */
void MetricsCollector::recordPacket(int id, bool is_malware, bool was_dropped, long long latency_ns) {
    logs_.push_back({id, is_malware ? 1 : 0, was_dropped ? 1 : 0, latency_ns});

    // Populate classification metrics
    if (was_dropped) {
        if (is_malware) true_positives_++;
        else            false_positives_++;
    } else {
        if (is_malware) false_negatives_++;
        else            true_negatives_++;
    }
}

/**
 * @brief Writes collected trajectory packet logs out to a raw CSV table.
 * 
 * @param filename Target file output path.
 * @return true if file writing succeeded, false otherwise.
 */
bool MetricsCollector::exportToCSV(const std::string& filename) const {
    std::ofstream csv_out(filename);
    if (!csv_out.is_open()) return false;

    csv_out << "packet_id,is_malware,was_dropped,latency_ns\n";
    for (const auto& log : logs_) {
        csv_out << log.id << "," << log.is_malware << ","
                << log.was_dropped << "," << log.latency << "\n";
    }
    csv_out.close();
    return true;
}

/**
 * @brief Computes rates and prints security performance statistics to the console.
 * 
 * @param total_packets Total packets processed.
 * @param malware_count Total attack packets injected.
 */
void MetricsCollector::printSecurityReport(int total_packets, int malware_count) const {
    double total_attacks = true_positives_ + false_negatives_;
    double total_normal  = true_negatives_ + false_positives_;

    std::cout << "\n========================================\n";
    std::cout << "      FILTER FSM SECURITY REPORT\n";
    std::cout << "========================================\n";
    std::cout << "Total Packets Processed : " << total_packets           << "\n";
    std::cout << "Total Malware Injected  : " << malware_count           << "\n";
    std::cout << "True Positives (Blocked): " << true_positives_          << " (Good!)\n";
    std::cout << "True Negatives (Passed) : " << true_negatives_          << " (Good!)\n";
    std::cout << "False Positives (Dropped normal) : " << false_positives_ << " (BAD - Self DoS)\n";
    std::cout << "False Negatives (Missed attack)  : " << false_negatives_ << " (BAD - Latency Risk)\n";
    
    // Output False Positive and False Negative rate calculations
    if (total_normal > 0) {
        std::cout << "False Positive Rate (FPR) : "
                  << (false_positives_ / total_normal) * 100.0 << "%\n";
    }
    if (total_attacks > 0) {
        std::cout << "False Negative Rate (FNR) : "
                  << (false_negatives_ / total_attacks) * 100.0 << "%\n";
    }
    std::cout << "========================================\n";
    std::cout << GREEN << "[+] Saved telemetry to output directory" << RESET << "\n";
}

} // namespace qos_harness