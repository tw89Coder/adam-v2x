#ifndef QOS_HARNESS_RL_BRIDGE_HPP
#define QOS_HARNESS_RL_BRIDGE_HPP

#include <fstream>
#include <string>

#include "qos_harness/pre_filter.hpp"

namespace qos_harness {

/**
 * @brief Structure holding defense policy parameters received from RL agent.
 */
struct FilterPolicy {
    double recovery_rate;
    double penalty_multiplier;
    int sq_threshold;
};

/**
 * @brief Structure holding aggregated window-level metrics sent to RL agent.
 */
struct WindowTelemetry {
    double avg_max_sum_sq;
    double avg_budget;
    double anomaly_rate;
};

/**
 * @brief OOP Bridge manager handling telemetry logging and socket synchronization with Python RL side.
 */
class RLBridge {
public:
    RLBridge(const std::string& repo_root, int port = 8080);
    ~RLBridge();

    // Delete copy semantics to prevent socket resource duplication
    RLBridge(const RLBridge&) = delete;
    RLBridge& operator=(const RLBridge&) = delete;

    /**
     * @brief Initializes file systems and configures execution mode with dynamic parameters.
     * @param enable_socket If true, activates real-time blocking TCP synchronization.
     * @param pollution_rate Current packet injection anomaly density profile.
     * @param attack_mode Target traffic pattern model logic index.
     */
    void initialize(bool enable_socket, double pollution_rate, int attack_mode);

    /**
     * @brief Logs per-packet metrics to the training trace file.
     */
    void collect_packet_telemetry(size_t pkt_size, int max_sum_sq, double budget, int state, bool is_anomalous);

    /**
     * @brief Checks window boundaries and synchronizes parameters with the RL controller.
     */
    void check_and_sync_window(int current_packet_idx, AdaptiveFilterFSM& filter);

private:
    std::string repo_root_;
    int port_;
    bool socket_enabled_;
    int server_fd_;

    // Window-level statistical accumulators
    const int CTRL_WINDOW_SIZE = 1000;
    int window_packet_count_ = 0;
    double window_sq_sum_ = 0;
    double window_budget_sum_ = 0;
    int window_malware_count_ = 0;

    std::ofstream csv_file_;

    void write_csv_header();
    bool handshake_with_agent(const WindowTelemetry& telemetry, FilterPolicy& out_policy);
};

}  // namespace qos_harness

#endif  // QOS_HARNESS_RL_BRIDGE_HPP