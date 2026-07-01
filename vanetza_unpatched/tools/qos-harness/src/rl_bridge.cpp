/**
 * @file rl_bridge.cpp
 * @brief Implementation of the reinforcement learning socket bridge interface.
 * 
 * DESIGN CONTEXT & WORKFLOW IPC LINK:
 * This class coordinates the telemetry gathering and bidirectional IPC synchronization
 * between the C++ simulator engine and the Python PyTorch/PPO training agent.
 * 
 * TELEMETRY LOGGING (EPISODIC TRACES):
 * Writes per-packet metrics (packet size, max similarity square, budget, state, anomalies)
 * to a CSV training trace. Each run routes to a rate-specific and mode-specific log 
 * file to prevent cross-run trace contamination.
 * 
 * CONTROL WINDOW & SOCKET HANDSHAKE:
 * - Aggregates packet statistics over a window of CTRL_WINDOW_SIZE (1000) packets.
 * - At window boundaries, it opens a blocking TCP socket loopback connection to port 8080.
 * - Sends a serialized telemetry observation string: "avg_max_sum_sq,avg_budget,anomaly_rate\n"
 * - Blocks execution waiting for the DRL policy decision, which is received as a serialized 
 *   comma-separated control string: "recovery,penalty,sq_threshold,s0_sampling_rate\n"
 * - Dynamically updates the FSM parameters with the newly received policy.
 */

#include "qos_harness/rl_bridge.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <iostream>

#ifdef USE_ONNX
#include <onnxruntime_cxx_api.h>
#include <vector>
#include <cmath>
#endif

namespace qos_harness {

RLBridge::RLBridge(const std::string& repo_root, int port)
    : repo_root_(repo_root), port_(port), socket_enabled_(false), server_fd_(-1),
      onnx_enabled_(false), onnx_model_path_("") {}

RLBridge::~RLBridge() {
    if (server_fd_ >= 0) {
        close(server_fd_);
    }
    if (csv_file_.is_open()) {
        csv_file_.close();
    }
}

/**
 * @brief Configures simulation outputs directory and routes traces to dynamic files.
 * 
 * @param enable_socket Enables active loopback TCP handshake updates if true.
 * @param pollution_rate Anomaly flow percentage representing fuzzer intensity.
 * @param attack_mode Selected traffic generator schedule index.
 */
void RLBridge::initialize(bool enable_socket, double pollution_rate, int attack_mode) {
    socket_enabled_ = enable_socket;

    // Create outputs folder for reinforcement learning offline/online telemetry
    std::string dir_path = repo_root_ + "/outputs/rl_env";
    mkdir(dir_path.c_str(), 0755);

    // Route trace files dynamically to prevent overlapping executions from overwriting matrices
    char file_path[512];
    std::snprintf(file_path, sizeof(file_path), "%s/training_trace_%.1f_mode%d.csv", dir_path.c_str(), pollution_rate,
                  attack_mode);

    // Open file using truncation to ensure clean episodic runs
    csv_file_.open(file_path, std::ios::out);
    write_csv_header();
}

void RLBridge::initialize_onnx(bool enable_onnx, const std::string& model_path) {
    onnx_enabled_ = enable_onnx;
    onnx_model_path_ = model_path;
}

void RLBridge::set_safety_guards(bool enabled) {
    safety_guards_enabled_ = enabled;
}

/**
 * @brief Commits CSV column labels if the telemetry file is empty.
 */
void RLBridge::write_csv_header() {
    csv_file_.seekp(0, std::ios::end);
    if (csv_file_.tellp() == 0) {
        csv_file_ << "packet_size,max_sum_sq,current_budget,fsm_state,is_anomalous\n";
    }
}

/**
 * @brief Logs packet-level observations and updates sliding window statisticians.
 * 
 * @param pkt_size Length of the raw packet.
 * @param max_sum_sq The maximum F2 sketch similarity count.
 * @param budget Virtual CPU budget value of the FSM.
 * @param state Current FSM state index (0 to 3).
 * @param is_anomalous True if the packet was dropped.
 */
void RLBridge::collect_packet_telemetry(size_t pkt_size, int max_sum_sq, double budget, int state, bool is_anomalous) {
    if (csv_file_.is_open()) {
        csv_file_ << pkt_size << "," << max_sum_sq << "," << budget << "," << state << "," << (is_anomalous ? 1 : 0)
                  << "\n";
    }

    // Accumulate sliding window statisticians
    window_packet_count_++;
    window_sq_sum_ += max_sum_sq;
    window_budget_sum_ += budget;
    if (is_anomalous) {
        window_malware_count_++;
    }
}

/**
 * @brief Synchronizes policy parameters with the python DRL brain at window boundary splits.
 * 
 * @param current_packet_idx The index of the packet in the main loop.
 * @param filter The active FSM instance to modify.
 */
void RLBridge::check_and_sync_window(int current_packet_idx, AdaptiveFilterFSM& filter) {
    if (window_packet_count_ < CTRL_WINDOW_SIZE) return;

    // Package window statistics
    WindowTelemetry telemetry{window_sq_sum_ / window_packet_count_, window_budget_sum_ / window_packet_count_,
                              static_cast<double>(window_malware_count_) / window_packet_count_};

    if (onnx_enabled_) {
        FilterPolicy next_policy{0.05, 50.0, 600, 0.10};
        if (run_onnx_inference(telemetry, next_policy)) {
            filter.update_policy_params(next_policy.recovery_rate, next_policy.penalty_multiplier,
                                        next_policy.sq_threshold, next_policy.base_sampling_rate);
        }
    } else if (socket_enabled_) {
        // Construct policy structure mapping baseline fallback configurations with 10% base sampling
        FilterPolicy next_policy{0.05, 50.0, 600, 0.10};

        // Handshake with the optimization engine and overwrite state machine parameters
        if (handshake_with_agent(telemetry, next_policy)) {
            // Apply safety boundaries in C++ if enabled
            if (safety_guards_enabled_) {
                if (next_policy.sq_threshold > 650) next_policy.sq_threshold = 650;
                if (next_policy.penalty_multiplier < 20.0) next_policy.penalty_multiplier = 20.0;
                if (next_policy.recovery_rate > 0.10) next_policy.recovery_rate = 0.10;
                if (next_policy.base_sampling_rate < 0.05) next_policy.base_sampling_rate = 0.05;
            }
            // Apply the received 4D parameter array to regulate filter thresholds and sampling rates
            filter.update_policy_params(next_policy.recovery_rate, next_policy.penalty_multiplier,
                                        next_policy.sq_threshold, next_policy.base_sampling_rate);
        }
    }

    // Reset window statistical accumulators
    window_packet_count_ = 0;
    window_sq_sum_ = 0;
    window_budget_sum_ = 0;
    window_malware_count_ = 0;
}

/**
 * @brief Connects to loopback port and executes a synchronous telemetry/policy handshake.
 * 
 * @param telemetry Aggregate input features.
 * @param out_policy Structured policy buffer to write model responses to.
 * @return true if communication succeeded and parameters were verified, false otherwise.
 */
bool RLBridge::handshake_with_agent(const WindowTelemetry& telemetry, FilterPolicy& out_policy) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port_);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    // Drop connection and fallback gracefully if the Python training server is offline
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock);
        return false;
    }

    // Serialize window statistics using the wire protocol format
    char send_buf[256];
    std::snprintf(send_buf, sizeof(send_buf), "%f,%f,%f\n", telemetry.avg_max_sum_sq, telemetry.avg_budget,
                  telemetry.anomaly_rate);
    send(sock, send_buf, std::strlen(send_buf), 0);

    // Block C++ thread and wait for DRL agent control updates
    char recv_buf[256] = {0};
    int valread = read(sock, recv_buf, sizeof(recv_buf) - 1);
    close(sock);

    if (valread <= 0) return false;

    // Deserialize incoming command string into separate parameters
    std::string res(recv_buf);
    size_t pos1 = res.find(',');
    size_t pos2 = res.find(',', pos1 + 1);
    size_t pos3 = res.find(',', pos2 + 1);  // Exposes the 4th active variable boundary

    // Reject envelopes missing token separators
    if (pos1 == std::string::npos || pos2 == std::string::npos || pos3 == std::string::npos) {
        return false;
    }

    // Extract policy tokens and write to output parameters
    out_policy.recovery_rate = std::stod(res.substr(0, pos1));
    out_policy.penalty_multiplier = std::stod(res.substr(pos1 + 1, pos2 - pos1 - 1));
    out_policy.sq_threshold = std::stoi(res.substr(pos2 + 1, pos3 - pos2 - 1));
    out_policy.base_sampling_rate = std::stod(res.substr(pos3 + 1));  // Dynamically regulated by DRL

    return true;
}

#ifdef USE_ONNX
bool RLBridge::run_onnx_inference(const WindowTelemetry& telemetry, FilterPolicy& out_policy) {
    try {
        // Initialize ONNX Runtime Env and Session on first call (thread-safe static initialization)
        static Ort::Env env(ORT_LOGGING_LEVEL_WARNING, "V2X_ONNX_Inference");
        static Ort::SessionOptions session_options;
        session_options.SetIntraOpNumThreads(1);
        session_options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
        
        static Ort::Session session(env, onnx_model_path_.c_str(), session_options);
        
        // Input Node Names and Shapes
        static Ort::AllocatorWithDefaultOptions allocator;
        static Ort::AllocatedStringPtr input_name_ptr = session.GetInputNameAllocated(0, allocator);
        static Ort::AllocatedStringPtr output_name_ptr = session.GetOutputNameAllocated(0, allocator);
        const char* input_name = input_name_ptr.get();
        const char* output_name = output_name_ptr.get();
        
        // Dynamic Dimension Inspection: check shape of output
        auto output_type_info = session.GetOutputTypeInfo(0);
        auto output_tensor_info = output_type_info.GetTensorTypeAndShapeInfo();
        std::vector<int64_t> output_shape = output_tensor_info.GetShape();
        
        // Output dimension is the last dimension of the shape array
        size_t action_dim = output_shape.back();

        // 1. Prepare Input Tensor (Shape: 1x3)
        // Replicate Python feature engineering alignment:
        // simulated_size = (anomaly_rate > 0.05) ? 1400.0 : 325.0
        // Features:
        // 0: simulated_size / 1500.0 (MAX_PACKET_SIZE)
        // 1: avg_max_sum_sq / 65025.0 (MAX_F2_SQ)
        // 2: anomaly_rate
        float simulated_size = (telemetry.anomaly_rate > 0.05f) ? 1400.0f : 325.0f;
        std::vector<int64_t> input_shape = {1, 3};
        std::vector<float> input_tensor_values = {
            simulated_size / 1500.0f,
            static_cast<float>(telemetry.avg_max_sum_sq / 65025.0),
            static_cast<float>(telemetry.anomaly_rate)
        };

        auto memory_info = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
        Ort::Value input_tensor = Ort::Value::CreateTensor<float>(
            memory_info, input_tensor_values.data(), input_tensor_values.size(),
            input_shape.data(), input_shape.size()
        );

        // 2. Run ONNX Session Inference
        const char* input_names[] = {input_name};
        const char* output_names[] = {output_name};
        
        auto output_tensors = session.Run(
            Ort::RunOptions{nullptr}, input_names, &input_tensor, 1, output_names, 1
        );

        float* float_output = output_tensors.front().GetTensorMutableData<float>();

        // 3. Dynamic Action Space Mapping (Handles 3D vs 4D outputs)
        if (action_dim == 4) {
            // 4D Action Space: [recovery, penalty, sq_thresh, sampling_rate]
            out_policy.recovery_rate = float_output[0] * 0.5;
            out_policy.penalty_multiplier = float_output[1] * 100.0;
            out_policy.sq_threshold = static_cast<int>(400 + (float_output[2] * 400));
            out_policy.base_sampling_rate = float_output[3]; // Sigmoid output [0.0, 1.0]
        } 
        else if (action_dim == 3) {
            // 3D Action Space: [recovery, penalty, sq_thresh]
            out_policy.recovery_rate = float_output[0] * 0.5;
            out_policy.penalty_multiplier = float_output[1] * 100.0;
            out_policy.sq_threshold = static_cast<int>(400 + (float_output[2] * 400));
            
            // Dynamic S0 Peacetime Active Inspection Sampling Rate calculation:
            // sampling_rate = (1 / risk_budget) * k * 100%
            // In C++, telemetry.avg_budget represents the average remaining CPU budget [0.0, 1.0].
            // To prevent division by zero, we enforce a minimum budget floor.
            double current_budget = telemetry.avg_budget;
            if (current_budget < 0.01) current_budget = 0.01;
            
            double k = 0.01; // Constant factor
            double calculated_rate = (1.0 / current_budget) * k;
            
            // Enforce bounds [0.0, 1.0]
            if (calculated_rate < 0.0) calculated_rate = 0.0;
            if (calculated_rate > 1.0) calculated_rate = 1.0;
            
            out_policy.base_sampling_rate = calculated_rate;
        } 
        else {
            std::cerr << "[WARNING] ONNX model returned unexpected action dimensions: " << action_dim << "\n";
            return false;
        }

        // 4. Enforce Heuristic Safety Boundaries to prevent RL from going crazy (FNR protection)
        if (safety_guards_enabled_) {
            if (out_policy.sq_threshold > 650) out_policy.sq_threshold = 650;
            if (out_policy.penalty_multiplier < 20.0) out_policy.penalty_multiplier = 20.0;
            if (out_policy.recovery_rate > 0.10) out_policy.recovery_rate = 0.10;
            if (out_policy.base_sampling_rate < 0.05) out_policy.base_sampling_rate = 0.05;
        }

        return true;
    } 
    catch (const std::exception& e) {
        std::cerr << "[ERROR] ONNX C++ Inference session failure: " << e.what() << "\n";
        return false;
    }
}
#else
bool RLBridge::run_onnx_inference(const WindowTelemetry& telemetry, FilterPolicy& out_policy) {
    std::cerr << "\n[FATAL] ONNX Runtime in-process inference was requested with model: " 
              << onnx_model_path_ << "\n";
    std::cerr << "[FATAL] ONNX Runtime C++ API is not yet integrated into the build matrix.\n";
    std::cerr << "[FATAL] Exiting execution gracefully as requested.\n";
    std::exit(1);
    return false;
}
#endif

}  // namespace qos_harness