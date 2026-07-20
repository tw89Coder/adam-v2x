#ifndef QOS_HARNESS_RL_BRIDGE_HPP
#define QOS_HARNESS_RL_BRIDGE_HPP

#include <fstream>
#include <string>
#include <deque>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

#include "qos_harness/pre_filter.hpp"

namespace qos_harness {

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
    double instant_sampling_rate;
    double anomaly_rate;
    double true_anomaly_rate; // Ground truth attack intensity (malware packets / total packets) in the window
};

#pragma pack(push, 1)
struct WindowTelemetryPayload {
    uint32_t tp_count;
    uint32_t tn_count;
    uint32_t fp_count;
    uint32_t fn_count;
    uint32_t inspected_count;
    uint64_t total_sq;
    uint64_t total_latency_ticks;
    float current_sampling_rate;
};
#pragma pack(pop)

/**
 * @brief Telemetry record stored in memory buffers and flushed to the output CSV file on disk.
 * @note DEVELOPER WARNING: This struct is strictly used for offline diagnostic analysis and 
 *       generating performance plots (such as budget vs attack intensity). 
 *       Do NOT remove fields (like 'budget') from this struct, otherwise it will break compilation
 *       and the Python plotting engine.
 */
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
     * @param enable_trace If true, logs packet-level telemetry (Default: true).
     */
    void initialize(bool enable_socket, double pollution_rate, int attack_mode, bool enable_trace = true);

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
     * @brief Diagnostic hook for testing ONNX outputs with mock inputs.
     */
    void run_onnx_test(const WindowTelemetry& telemetry, FilterPolicy& out_policy) {
        run_onnx_inference(telemetry, out_policy);
    }

    /**
     * @brief Logs per-packet metrics to the training trace file.
     * @param pkt_size Length of the raw packet.
     * @param max_sum_sq The maximum F2 similarity count.
     * @param budget Virtual CPU budget value of the FSM.
     * @param state Current FSM state index (0 to 3).
     * @param is_anomalous True if the packet was flagged as anomalous/dropped.
     * @param is_malware True if the packet is ground truth malware.
     * @param inspected True if the packet was selected for inspection.
     * @param latency_ticks CPU TSC ticks spent on the F2 similarity check.
     */
    void collect_packet_telemetry(size_t pkt_size, int max_sum_sq, double budget, int state, bool is_anomalous, bool is_malware, bool inspected, uint64_t latency_ticks);

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
    
    // Instance-level variables for frame stacking to prevent cross-node data leakage
    bool history_initialized_ = false;
    std::vector<float> input_history_buffer_;

    /**
     * @brief Executes in-process ONNX model inference.
     * @return true if inference succeeded, false otherwise.
     */
    bool run_onnx_inference(const WindowTelemetry& telemetry, FilterPolicy& out_policy);

    // Window-level statistical accumulators
    const int CTRL_WINDOW_SIZE = 100;
    uint32_t window_tp_count_ = 0;
    uint32_t window_tn_count_ = 0;
    uint32_t window_fp_count_ = 0;
    uint32_t window_fn_count_ = 0;
    uint32_t window_inspected_count_ = 0;
    uint64_t window_sq_sum_ = 0;
    uint64_t window_latency_ticks_ = 0;
    
    std::ofstream csv_file_;
    std::ofstream window_csv_file_;
    std::vector<PacketTelemetry> packet_buffer_;
    int window_idx_ = 0;
    std::string algorithm_ = "dqn";
    std::vector<float> dqn_action_map_;

    /**
     * @brief Flushes buffered telemetry data to the CSV file on disk.
     */
    void flush_telemetry_buffer();

    void write_csv_header();
    bool handshake_with_agent(const WindowTelemetryPayload& payload, FilterPolicy& out_policy);

    // Multi-threaded ONNX background worker variables
    std::thread onnx_thread_;
    std::mutex onnx_mutex_;
    std::condition_variable onnx_cv_;
    std::atomic<bool> stop_onnx_thread_{false};
    std::atomic<bool> new_telemetry_available_{false};
    std::atomic<bool> new_policy_available_{false};

    // Shared communication buffers
    WindowTelemetry shared_telemetry_;
    FilterPolicy shared_policy_;

    /**
     * @brief Worker loop function executed by the background ONNX inference thread.
     */
    void onnx_worker_loop();

    /**
     * @brief Retrieves the list of CPU core indices assigned to this process.
     * @return Vector of allowed core IDs.
     */
    std::vector<int> get_allowed_cores();
};

}  // namespace qos_harness

#endif  // QOS_HARNESS_RL_BRIDGE_HPP
