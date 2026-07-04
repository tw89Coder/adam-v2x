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
    // Batching Optimization: Flush any remaining packet data in the buffer to disk before closing the file.
    flush_telemetry_buffer();
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

    std::string dir_path;
    char file_path[512];

    if (socket_enabled_) {
        // [DRL Training Mode] output to outputs/rl_env
        dir_path = repo_root_ + "/outputs/rl_env";
        mkdir(dir_path.c_str(), 0755);
        std::snprintf(file_path, sizeof(file_path), "%s/training_trace_%.1f_mode%d.csv", dir_path.c_str(), pollution_rate,
                      attack_mode);
    } else {
        // [Manual Trace Mode] output to outputs/traces/{build_type}/
        std::string build_type = "unpatched";
        if (repo_root_.find("vanetza_patched") != std::string::npos) {
            build_type = "patched";
        }

        std::string base_dir = repo_root_ + "/outputs/traces";
        mkdir(base_dir.c_str(), 0755);
        dir_path = base_dir + "/" + build_type;
        mkdir(dir_path.c_str(), 0755);

        std::snprintf(file_path, sizeof(file_path), "%s/fsm_trace_rate_%.1f_mode%d.csv", dir_path.c_str(), pollution_rate,
                      attack_mode);
    }

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

void RLBridge::collect_packet_telemetry(size_t pkt_size, int max_sum_sq, double budget, int state, bool is_anomalous, bool is_malware) {
    if (csv_file_.is_open()) {
        // Batching Optimization: Instead of performing disk writes on every single packet (which wastes CPU cycles on IO),
        // we store the data in an in-memory buffer and batch-flush it.
        packet_buffer_.push_back({pkt_size, max_sum_sq, budget, state, is_anomalous});
        if (packet_buffer_.size() >= static_cast<size_t>(CTRL_WINDOW_SIZE)) {
            flush_telemetry_buffer();
        }
    }
    
    //===================================================================================
    //================== Chi-Aan: An array of each packet's features . ==================
    //===================================================================================
    PacketFeature feat{
        static_cast<float>(pkt_size) / 1500.0f,
        static_cast<float>(max_sum_sq) / 65025.0f,
        is_anomalous ? 1.0f : 0.0f
    };

    packet_feature_arr.push_back(feat);

    if (packet_feature_arr.size() > OBS_HISTORY_LEN) {
        packet_feature_arr.pop_front();
    }

    // Accumulate sliding window statistics for DQN/PPO observations
    window_packet_count_++;
    window_sq_sum_ += max_sum_sq;
    window_budget_sum_ += budget;
    if (is_anomalous) {
        window_malware_count_++;
    }
    if (is_malware) {
        window_real_malware_count_++;
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
    WindowTelemetry telemetry{
        window_sq_sum_ / window_packet_count_,
        filter.get_sampling_rate(),
        static_cast<double>(window_malware_count_) / window_packet_count_,
        static_cast<double>(window_real_malware_count_) / window_packet_count_
    };

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
    window_real_malware_count_ = 0;
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

    // Serialize window statistics using the wire protocol format:
    // Format: avg_max_sum_sq, instant_sampling_rate, anomaly_rate, true_anomaly_rate
    char send_buf[256];
    std::snprintf(send_buf, sizeof(send_buf), "%f,%f,%f,%f\n", telemetry.avg_max_sum_sq, telemetry.instant_sampling_rate,
                  telemetry.anomaly_rate, telemetry.true_anomaly_rate);
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
    // CWE-248 Mitigation: Wrap string-to-numeric conversions in a try-catch block.
    // If the socket receives malformed, incomplete data, or non-numeric error output from Python,
    // stod/stoi throws exceptions. Catching them prevents the simulator from crashing,
    // allowing the caller to fallback to safe baseline heuristic parameters.
    try {
        out_policy.recovery_rate = std::stod(res.substr(0, pos1));
        out_policy.penalty_multiplier = std::stod(res.substr(pos1 + 1, pos2 - pos1 - 1));
        out_policy.sq_threshold = std::stoi(res.substr(pos2 + 1, pos3 - pos2 - 1));
        out_policy.base_sampling_rate = std::stod(res.substr(pos3 + 1));  // Dynamically regulated by DRL
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Parsing policy variables from network failed: " << e.what() << "\n";
        return false;
    }

    return true;
}

#ifdef USE_ONNX
bool RLBridge::run_onnx_inference(const WindowTelemetry& telemetry, FilterPolicy& out_policy) {
    try {
        // ONNX Environment and Session initialization.
        // Using "static" ensures that the ONNX Environment, session options, and network weights
        // are loaded and compiled exactly once on the first call (lazy initialization).
        // This is safe since the simulation engine runs on a single main thread.
        static Ort::Env env(ORT_LOGGING_LEVEL_WARNING, "V2X_ONNX_Inference");
        static Ort::SessionOptions session_options;
        
        // Single-threaded configuration: 
        // Force ONNX Runtime to use exactly 1 thread for internal operators. This eliminates OS scheduling jitter,
        // context-switch overhead, and potential CPU resource contention with the V2X simulator's main thread.
        session_options.SetIntraOpNumThreads(1);
        session_options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
        
        // Load the ONNX model from the specified filesystem path and instantiate the session.
        static Ort::Session session(env, onnx_model_path_.c_str(), session_options);
        
        // Inspect model input/output metadata.
        // We retrieve the static input and output names using the default allocator.
        static Ort::AllocatorWithDefaultOptions allocator;
        static Ort::AllocatedStringPtr input_name_ptr = session.GetInputNameAllocated(0, allocator);
        static Ort::AllocatedStringPtr output_name_ptr = session.GetOutputNameAllocated(0, allocator);
        const char* input_name = input_name_ptr.get();
        const char* output_name = output_name_ptr.get();
        
        // Dynamic Dimension Inspection:
        // Read output tensor description to determine the model's action dimension dynamically.
        // This allows C++ to seamlessly support 2D, 3D, or 4D models without code modifications.
        auto output_type_info = session.GetOutputTypeInfo(0);
        auto output_tensor_info = output_type_info.GetTensorTypeAndShapeInfo();
        std::vector<int64_t> output_shape = output_tensor_info.GetShape();
        
        // The last element of output shape vector is the action dimension (e.g. 2, 3, or 4).
        size_t action_dim = output_shape.back();

        // 1. Prepare Input Tensor (Shape: 1x3)
        // Feature Engineering Alignment:
        // Construct the normalized 3D state vector exactly matching Python training pipelines.
        // Simulated packet size is mapped stochastically depending on anomaly rate (325.0 during nominal, 1400.0 during attack).
        // Features:
        // [0]: normalized_packet_size (0.0 to 1.0)
        // [1]: normalized_max_f2_similarity (0.0 to 1.0)
        // [2]: raw_anomaly_rate (0.0 to 1.0)
        float simulated_size = (telemetry.anomaly_rate > 0.05f) ? 1400.0f : 325.0f;
        std::vector<int64_t> input_shape = {1, 3};
        std::vector<float> input_tensor_values = {
            simulated_size / 1500.0f,
            static_cast<float>(telemetry.avg_max_sum_sq / 65025.0),
            static_cast<float>(telemetry.anomaly_rate)
        };

        // Create the CPU tensor representation. The memory is allocated locally on the thread's stack.
        auto memory_info = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
        Ort::Value input_tensor = Ort::Value::CreateTensor<float>(
            memory_info, input_tensor_values.data(), input_tensor_values.size(),
            input_shape.data(), input_shape.size()
        );

        // 2. Execute ONNX Model Inference (Synchronous feedforward pass)
        const char* input_names[] = {input_name};
        const char* output_names[] = {output_name};
        
        auto output_tensors = session.Run(
            Ort::RunOptions{nullptr}, input_names, &input_tensor, 1, output_names, 1
        );

        // Retrieve raw floating point outputs from the output tensor.
        float* float_output = output_tensors.front().GetTensorMutableData<float>();

        // 3. Dynamic Action Space Mapping (Adapts to model complexity)
        if (action_dim == 4) {
            // 4D Model Output: [recovery_rate, penalty_multiplier, sq_threshold, base_sampling_rate]
            out_policy.recovery_rate = float_output[0] * 0.5;
            out_policy.penalty_multiplier = float_output[1] * 100.0;
            out_policy.sq_threshold = static_cast<int>(400 + (float_output[2] * 400));
            out_policy.base_sampling_rate = float_output[3];
        } 
        else if (action_dim == 3) {
            // 3D Model Output: [recovery_rate, penalty_multiplier, sq_threshold]
            out_policy.recovery_rate = float_output[0] * 0.5;
            out_policy.penalty_multiplier = float_output[1] * 100.0;
            out_policy.sq_threshold = static_cast<int>(400 + (float_output[2] * 400));
            
            // For 3D models, directly apply the current instant sampling rate
            out_policy.base_sampling_rate = telemetry.instant_sampling_rate;
        } 
        else if (action_dim == 2) {
            // 2D Model Output: [recovery_rate, penalty_multiplier]
            out_policy.recovery_rate = float_output[0] * 0.5;
            out_policy.penalty_multiplier = float_output[1] * 100.0;
            
            // Set static defaults for remaining unmanaged variables
            out_policy.sq_threshold = 650;
            out_policy.base_sampling_rate = 0.05;
        }
        else {
            std::cerr << "[WARNING] ONNX model returned unexpected action dimensions: " << action_dim << "\n";
            return false;
        }

        // 4. Heuristic Safety Clamping (Layer 2 Safeguard)
        // Keeps actions bounded within empirically proven safety limits to guarantee FNR performance floors.
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

void RLBridge::flush_telemetry_buffer() {
    if (csv_file_.is_open() && !packet_buffer_.empty()) {
        for (const auto& pkt : packet_buffer_) {
            csv_file_ << pkt.pkt_size << "," << pkt.max_sum_sq << "," << pkt.budget << "," << pkt.state << ","
                      << (pkt.is_anomalous ? 1 : 0) << "\n";
        }
        packet_buffer_.clear();
    }
}

}  // namespace qos_harness