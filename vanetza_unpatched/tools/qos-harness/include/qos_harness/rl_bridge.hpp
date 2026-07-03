#ifndef QOS_HARNESS_RL_BRIDGE_HPP
#define QOS_HARNESS_RL_BRIDGE_HPP

#include <fstream>
#include <string>
#include <deque>
#include <vector>

#include "qos_harness/pre_filter.hpp"

namespace qos_harness {

//==================================================================
//======chian: Packet Feature Array ================================
//==================================================================
/**
 * @brief an entity in array presents the packet feartures 
 */
    struct PacketFeature {
    float packet_size_norm;
    float max_sum_sq_norm;
    float is_anomalous;
};

static constexpr size_t OBS_HISTORY_LEN = 100;

//==================================================================

/**
 * @brief Structure holding defense policy parameters received from RL agent.
 */
struct FilterPolicy {
    double recovery_rate;
    double penalty_multiplier;
    int sq_threshold;
    double base_sampling_rate;
};

/**
 * @brief Structure holding aggregated window-level metrics sent to RL agent.
 */
struct WindowTelemetry {
    double avg_max_sum_sq;
    double avg_budget;
    double anomaly_rate;
};

struct PacketTelemetry {
    size_t pkt_size;
    int max_sum_sq;
    double budget;
    int state;
    bool is_anomalous;
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
     * @brief Configures ONNX inference state.
     * @param enable_onnx If true, prepares system to run in-process ONNX model inference.
     * @param model_path Path to the exported ONNX model binary.
     */
    void initialize_onnx(bool enable_onnx, const std::string& model_path);

    /**
     * @brief Set safety guards (heuristic boundaries) status.
     * @param enabled If true, safety boundaries clamp RL outputs.
     */
    void set_safety_guards(bool enabled);

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
    bool onnx_enabled_;
    std::string onnx_model_path_;
    bool safety_guards_enabled_ = true;

    /**
     * @brief Executes in-process ONNX model inference.
     * @return true if inference succeeded, false otherwise.
     */
    bool run_onnx_inference(const WindowTelemetry& telemetry, FilterPolicy& out_policy);

    // Window-level statistical accumulators
    const int CTRL_WINDOW_SIZE = 1000;
    int window_packet_count_ = 0;
    double window_sq_sum_ = 0;
    double window_budget_sum_ = 0;
    int window_malware_count_ = 0;

    std::deque<PacketFeature> packet_history_;
    std::ofstream csv_file_;
    std::vector<PacketTelemetry> packet_buffer_;

    /**
     * @brief Flushes buffered telemetry data to the CSV file on disk.
     */
    void flush_telemetry_buffer();

    void write_csv_header();
    bool handshake_with_agent(const WindowTelemetry& telemetry, FilterPolicy& out_policy);
};

}  // namespace qos_harness

#endif  // QOS_HARNESS_RL_BRIDGE_HPP