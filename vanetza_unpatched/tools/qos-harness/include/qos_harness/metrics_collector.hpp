#ifndef QOS_HARNESS_METRICS_COLLECTOR_HPP
#define QOS_HARNESS_METRICS_COLLECTOR_HPP

#include <string>
#include <vector>

namespace qos_harness {

struct LogRecord {
    int id;
    int is_malware;
    int was_dropped;
    long long latency;
};

class MetricsCollector {
public:
    MetricsCollector();

    /**
     * @brief Reserves memory for the logs vector to avoid reallocations.
     * @param total_packets Expected total number of packets in the simulation.
     */
    void reserve(size_t total_packets);

    /**
     * @brief Records telemetry data for a processed packet and updates the confusion matrix.
     */
    void recordPacket(int id, bool is_malware, bool was_dropped, long long latency_ns);

    /**
     * @brief Exports all recorded telemetry logs into a standard CSV format.
     * @param filename Target destination path for the CSV file.
     * @return true If file write succeeds.
     */
    bool exportToCSV(const std::string& filename) const;

    /**
     * @brief Prints a formatted, high-visibility security and performance report to stdout.
     * @param total_packets The total number of packets simulated.
     * @param malware_count The total number of malicious packets injected.
     */
    void printSecurityReport(int total_packets, int malware_count) const;

private:
    std::vector<LogRecord> logs_;
    
    // Confusion Matrix attributes
    mutable int true_positives_;
    mutable int false_positives_;
    mutable int true_negatives_;
    mutable int false_negatives_;
};

} // namespace qos_harness

#endif // QOS_HARNESS_METRICS_COLLECTOR_HPP