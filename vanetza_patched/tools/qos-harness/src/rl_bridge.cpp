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
#include "qos_harness/console_presenter.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sched.h>
#include <pthread.h>

#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <fstream>
#include <algorithm>

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
    stop_onnx_thread_ = true;
    onnx_cv_.notify_all();
    if (onnx_thread_.joinable()) {
        onnx_thread_.join();
    }
    if (server_fd_ >= 0) {
        close(server_fd_);
    }
    // Batching Optimization: Flush any remaining packet data in the buffer to disk before closing the file.
    flush_telemetry_buffer();
    if (csv_file_.is_open()) {
        csv_file_.close();
    }
    if (window_csv_file_.is_open()) {
        window_csv_file_.close();
    }
}

/**
 * @brief Configures simulation outputs directory and routes traces to dynamic files.
 * 
 * @param enable_socket Enables active loopback TCP handshake updates if true.
 * @param pollution_rate Anomaly flow percentage representing fuzzer intensity.
 * @param attack_mode Selected traffic generator schedule index.
 */
void RLBridge::initialize(bool enable_socket, double pollution_rate, int attack_mode, bool enable_trace) {
    socket_enabled_ = enable_socket;

    // Reset episodic states to prevent cross-run telemetry pollution
    history_initialized_ = false;
    input_history_buffer_.clear();
    packet_buffer_.clear();
    window_idx_ = 0;

    window_tp_count_ = 0;
    window_tn_count_ = 0;
    window_fp_count_ = 0;
    window_fn_count_ = 0;
    window_inspected_count_ = 0;
    window_sq_sum_ = 0;
    window_latency_ticks_ = 0;

    std::string build_type = "unpatched";
    std::string source_file = __FILE__;
    if (source_file.find("vanetza_patched") != std::string::npos) {
        build_type = "patched";
    }

    std::string parent_dir = repo_root_ + "/outputs/rl_env";
    std::string dir_path = parent_dir + "/" + build_type;
    mkdir(parent_dir.c_str(), 0755);
    mkdir(dir_path.c_str(), 0755);

    std::string suffix = "filtered";
    if (socket_enabled_) {
        suffix = "rl";
    } else if (onnx_enabled_) {
        suffix = "onnx";
    }

    char file_path[512];
    char win_file_path[512];
    std::snprintf(file_path, sizeof(file_path), "%s/training_trace_%.1f_mode%d_%s.csv", dir_path.c_str(), pollution_rate,
                  attack_mode, suffix.c_str());
    std::snprintf(win_file_path, sizeof(win_file_path), "%s/window_trace_%.1f_mode%d_%s.csv", dir_path.c_str(), pollution_rate,
                  attack_mode, suffix.c_str());

    if (csv_file_.is_open()) csv_file_.close();
    if (enable_trace || socket_enabled_) {
        csv_file_.open(file_path, std::ios::out);
        write_csv_header();
    }

    if (window_csv_file_.is_open()) window_csv_file_.close();
    if (enable_trace || socket_enabled_) {
        window_csv_file_.open(win_file_path, std::ios::out);
        if (window_csv_file_.is_open()) {
            window_csv_file_ << "window_index,actual_inspection_rate,target_sampling_rate,attack_intensity,fpr,fnr,avg_sq,tp,tn,fp,fn\n";
        }
    }
}

void RLBridge::initialize_onnx(bool enable_onnx, const std::string& model_path) {
    onnx_enabled_ = enable_onnx;
    onnx_model_path_ = model_path;

    if (onnx_enabled_) {
        // 1. Ensure the ONNX model file exists to prevent silent execution fallback
        struct stat st;
        if (stat(onnx_model_path_.c_str(), &st) != 0) {
            std::cerr << "\n[FATAL] ONNX Model file not found at path: " << onnx_model_path_ << "\n";
            std::cerr << "[FATAL] Please verify the path or export the model first.\n";
            std::exit(1);
        }

        // 2. Dynamically parse agent.yaml to read algorithm and action_map
        algorithm_ = "dqn"; // Default fallback
        dqn_action_map_ = {-0.10f, -0.05f, 0.0f, 0.05f, 0.10f}; // Default fallback

        std::string config_path = repo_root_ + "/tools/rl_bridge/config/agent.yaml";
        std::ifstream config_file(config_path);
        if (config_file.is_open()) {
            std::string line;
            while (std::getline(config_file, line)) {
                // Strip comments first
                size_t comment_pos = line.find('#');
                if (comment_pos != std::string::npos) {
                    line = line.substr(0, comment_pos);
                }

                // Find algorithm: "..."
                size_t algo_pos = line.find("algorithm:");
                if (algo_pos != std::string::npos) {
                    std::string val = line.substr(algo_pos + 10);
                    val.erase(0, val.find_first_not_of(" \t\"'"));
                    val.erase(val.find_last_not_of(" \t\"'") + 1);
                    for (auto& c : val) c = std::tolower(c);
                    algorithm_ = val;
                }

                // Find action_map: [...]
                size_t map_pos = line.find("action_map:");
                if (map_pos != std::string::npos) {
                    size_t start_bracket = line.find('[', map_pos);
                    size_t end_bracket = line.find(']', map_pos);
                    if (start_bracket != std::string::npos && end_bracket != std::string::npos) {
                        std::string array_str = line.substr(start_bracket + 1, end_bracket - start_bracket - 1);
                        std::vector<float> parsed_map;
                        std::stringstream ss(array_str);
                        std::string token;
                        try {
                            while (std::getline(ss, token, ',')) {
                                token.erase(0, token.find_first_not_of(" \t"));
                                token.erase(token.find_last_not_of(" \t") + 1);
                                if (!token.empty()) {
                                    parsed_map.push_back(std::stof(token));
                                }
                            }
                            if (!parsed_map.empty()) {
                                dqn_action_map_ = parsed_map;
                            }
                        } catch (...) {
                            // Keep default fallback on parse error
                        }
                    }
                }
            }
            config_file.close();
        }
        std::cout << "\n[INIT] C++ ONNX Bridge initialized dynamically:\n"
                  << "  └── Algorithm detected: " << algorithm_ << "\n"
                  << "  └── Action space map size: " << dqn_action_map_.size() << "\n"
                  << "  └── Model path verified: " << onnx_model_path_ << "\n\n";

        stop_onnx_thread_ = false;
        new_telemetry_available_ = false;
        new_policy_available_ = false;
        onnx_thread_ = std::thread(&RLBridge::onnx_worker_loop, this);
    }
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

void RLBridge::collect_packet_telemetry(size_t pkt_size, int max_sum_sq, double budget, int state, bool is_anomalous, bool is_malware, bool inspected, uint64_t latency_ticks) {
    if (csv_file_.is_open()) {
        // Batching Optimization: Instead of performing disk writes on every single packet (which wastes CPU cycles on IO),
        // we store the data in an in-memory buffer and batch-flush it.
        packet_buffer_.push_back({pkt_size, max_sum_sq, budget, state, is_anomalous});
        if (packet_buffer_.size() >= static_cast<size_t>(CTRL_WINDOW_SIZE)) {
            flush_telemetry_buffer();
        }
    }
    


    // Classify packet into confusion matrix categories for structural byte dumping
    if (is_malware) {
        if (is_anomalous) {
            window_tp_count_++;
        } else {
            window_fn_count_++; // Malware allowed = Leakage
        }
    } else {
        if (is_anomalous) {
            window_fp_count_++; // Benign dropped = False Positive
        } else {
            window_tn_count_++; // Benign allowed = True Negative
        }
    }

    if (inspected) {
        window_inspected_count_++;
    }

    window_sq_sum_ += max_sum_sq;
    window_latency_ticks_ += latency_ticks;
}

/**
 * @brief Synchronizes policy parameters with the python DRL brain at window boundary splits.
 * 
 * @param current_packet_idx The index of the packet in the main loop.
 * @param filter The active FSM instance to modify.
 */
void RLBridge::check_and_sync_window(int current_packet_idx, AdaptiveFilterFSM& filter) {
    // 1. Check if background thread computed a new policy
    if (new_policy_available_.load(std::memory_order_acquire)) {
        FilterPolicy policy;
        {
            std::lock_guard<std::mutex> lock(onnx_mutex_);
            policy = shared_policy_;
        }
        if (safety_guards_enabled_) {
            if (policy.sq_threshold > 650) policy.sq_threshold = 650;
            if (policy.penalty_multiplier < 20.0) policy.penalty_multiplier = 20.0;
            if (policy.recovery_rate > 0.10) policy.recovery_rate = 0.10;
            if (policy.base_sampling_rate < 0.05) policy.base_sampling_rate = 0.05;
        }
        filter.update_policy_params(policy.recovery_rate, policy.penalty_multiplier,
                                    policy.sq_threshold, policy.base_sampling_rate);
        new_policy_available_.store(false, std::memory_order_release);
    }

    uint32_t total_packets = window_tp_count_ + window_tn_count_ + window_fp_count_ + window_fn_count_;
    if (total_packets < static_cast<uint32_t>(CTRL_WINDOW_SIZE)) return;

    // Package binary structure payload
    WindowTelemetryPayload payload;
    payload.tp_count = window_tp_count_;
    payload.tn_count = window_tn_count_;
    payload.fp_count = window_fp_count_;
    payload.fn_count = window_fn_count_;
    payload.inspected_count = window_inspected_count_;
    payload.total_sq = window_sq_sum_;
    payload.total_latency_ticks = window_latency_ticks_;
    payload.current_sampling_rate = static_cast<float>(filter.get_sampling_rate());

    if (onnx_enabled_) {
        // Asynchronously hand off telemetry to the background ONNX thread
        {
            std::lock_guard<std::mutex> lock(onnx_mutex_);
            shared_telemetry_ = WindowTelemetry{
                static_cast<double>(window_sq_sum_) / total_packets,
                filter.get_sampling_rate(),
                static_cast<double>(window_tp_count_ + window_fp_count_) / total_packets,
                static_cast<double>(window_tp_count_ + window_fn_count_) / total_packets
            };
        }
        new_telemetry_available_.store(true, std::memory_order_release);
        onnx_cv_.notify_one();
    } else if (socket_enabled_) {
        FilterPolicy next_policy{0.05, 50.0, 600, 0.10};

        // Handshake with the optimization engine using binary struct
        if (handshake_with_agent(payload, next_policy)) {
            // Apply safety boundaries in C++ if enabled
            if (safety_guards_enabled_) {
                if (next_policy.sq_threshold > 650) next_policy.sq_threshold = 650;
                if (next_policy.penalty_multiplier < 20.0) next_policy.penalty_multiplier = 20.0;
                if (next_policy.recovery_rate > 0.10) next_policy.recovery_rate = 0.10;
                if (next_policy.base_sampling_rate < 0.05) next_policy.base_sampling_rate = 0.05;
            }
            filter.update_policy_params(next_policy.recovery_rate, next_policy.penalty_multiplier,
                                        next_policy.sq_threshold, next_policy.base_sampling_rate);
        }
    }
    // Write window-level metrics to window CSV log
    if (window_csv_file_.is_open()) {
        double actual_insp = (total_packets > 0) ? (static_cast<double>(window_inspected_count_) / total_packets) : 0.0;
        double target_samp = filter.get_sampling_rate();
        double attack_int = (total_packets > 0) ? (static_cast<double>(window_tp_count_ + window_fn_count_) / total_packets) : 0.0;
        
        double fpr = (window_fp_count_ + window_tn_count_ > 0) ? 
            (static_cast<double>(window_fp_count_) / (window_fp_count_ + window_tn_count_)) : 0.0;
        double fnr = (window_tp_count_ + window_fn_count_ > 0) ? 
            (static_cast<double>(window_fn_count_) / (window_tp_count_ + window_fn_count_)) : 0.0;
        double avg_sq = (total_packets > 0) ? (static_cast<double>(window_sq_sum_) / total_packets) : 0.0;

        window_csv_file_ << window_idx_++ << ","
                         << actual_insp << ","
                         << target_samp << ","
                         << attack_int << ","
                         << fpr << ","
                         << fnr << ","
                         << avg_sq << ","
                         << window_tp_count_ << ","
                         << window_tn_count_ << ","
                         << window_fp_count_ << ","
                         << window_fn_count_ << "\n";
    }
    // Reset window statistical accumulators
    window_tp_count_ = 0;
    window_tn_count_ = 0;
    window_fp_count_ = 0;
    window_fn_count_ = 0;
    window_inspected_count_ = 0;
    window_sq_sum_ = 0;
    window_latency_ticks_ = 0;
}

/**
 * @brief Connects to loopback port and executes a synchronous telemetry/policy handshake.
 * 
 * @param telemetry Aggregate input features.
 * @param out_policy Structured policy buffer to write model responses to.
 * @return true if communication succeeded and parameters were verified, false otherwise.
 */
bool RLBridge::handshake_with_agent(const WindowTelemetryPayload& payload, FilterPolicy& out_policy) {
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

    // Send binary telemetry payload directly (byte dumping)
    send(sock, &payload, sizeof(payload), 0);

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

        // 1. Prepare Current Features (Shape: 1x3)
        // Feature Engineering Alignment:
        // Construct the normalized 3D state vector exactly matching Python training pipelines.
        // Features:
        // [0]: instant_sampling_rate (0.0 to 1.0)
        // [1]: normalized_max_f2_similarity (0.0 to 1.0)
        // [2]: raw_anomaly_rate (0.0 to 1.0)
        std::vector<float> current_features = {
            static_cast<float>(telemetry.instant_sampling_rate),
            static_cast<float>(telemetry.avg_max_sum_sq / 65025.0),
            static_cast<float>(telemetry.anomaly_rate)
        };

        // --- NEW: DYNAMIC DIMENSION INSPECTION ---
        static auto input_type_info = session.GetInputTypeInfo(0);
        static auto input_tensor_info = input_type_info.GetTensorTypeAndShapeInfo();
        static std::vector<int64_t> model_input_shape = input_tensor_info.GetShape();
        static int64_t model_input_dim = model_input_shape.back(); // e.g. 3 or 12
        
        const size_t FEATURE_DIM = 3;
        static size_t K = model_input_dim / FEATURE_DIM;
        
        // --- NEW: PRE-ALLOCATED ZERO-ALLOCATION INSTANCE BUFFER ---
        if (input_history_buffer_.empty()) {
            input_history_buffer_.resize(model_input_dim, 0.0f);
        }

        // 2. Manage Frame History Buffer (Zero-Allocation ring shifting)
        if (!history_initialized_) {
            // Fill history buffer by repeating the first frame K times
            for (size_t i = 0; i < K; ++i) {
                std::copy(current_features.begin(), current_features.end(), 
                          input_history_buffer_.begin() + i * FEATURE_DIM);
            }
            history_initialized_ = true;
        } else {
            if (K > 1) {
                // Shift older frames to the left by FEATURE_DIM
                std::copy(input_history_buffer_.begin() + FEATURE_DIM, 
                          input_history_buffer_.end(), 
                          input_history_buffer_.begin());
                // Place new frame at the end of the history
                std::copy(current_features.begin(), current_features.end(), 
                          input_history_buffer_.end() - FEATURE_DIM);
            } else {
                input_history_buffer_ = current_features;
            }
        }

        // 3. Prepare Input Tensor (Using the contiguous flat history vector)
        std::vector<int64_t> input_shape = {1, static_cast<int64_t>(model_input_dim)};
        auto memory_info = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
        Ort::Value input_tensor = Ort::Value::CreateTensor<float>(
            memory_info, input_history_buffer_.data(), input_history_buffer_.size(),
            input_shape.data(), input_shape.size()
        );

        // 2. Execute ONNX Model Inference (Synchronous feedforward pass)
        const char* input_names[] = {input_name};
        const char* output_names[] = {output_name};
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        auto output_tensors = session.Run(
            Ort::RunOptions{nullptr}, input_names, &input_tensor, 1, output_names, 1
        );
        
        auto end_time = std::chrono::high_resolution_clock::now();
        uint64_t elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();
        total_inference_time_us_ += elapsed_us;
        inference_count_++;

        // Retrieve raw floating point outputs from the output tensor.
        float* float_output = output_tensors.front().GetTensorMutableData<float>();

        // 3. Explicit Algorithm Mapping (DQN vs PPO)
        if (algorithm_ == "dqn") {
            if (action_dim == dqn_action_map_.size()) {
                // ==========================================
                // [Raw DQN Model Mapping] Q-values output
                // ==========================================
                int best_action_idx = 0;
                float max_q_value = float_output[0];
                for (size_t i = 1; i < dqn_action_map_.size(); ++i) {
                    if (float_output[i] > max_q_value) {
                        max_q_value = float_output[i];
                        best_action_idx = i;
                    }
                }

                float delta = dqn_action_map_[best_action_idx];
                float new_rate = telemetry.instant_sampling_rate + delta;
                if (new_rate < 0.05f) new_rate = 0.05f;
                if (new_rate > 1.0f) new_rate = 1.0f;

                out_policy.recovery_rate = 0.05;
                out_policy.penalty_multiplier = 50.0;
                out_policy.sq_threshold = 600;
                out_policy.base_sampling_rate = new_rate;
            }
            else if (action_dim == 4) {
                // ==========================================
                // [Wrapped DQN Model Mapping] DQNDeploymentWrapper
                // ==========================================
                out_policy.recovery_rate = float_output[0] * 0.5;
                out_policy.penalty_multiplier = float_output[1] * 100.0;
                out_policy.sq_threshold = static_cast<int>(400 + (float_output[2] * 400));
                out_policy.base_sampling_rate = float_output[3];
            }
            else {
                std::cerr << "[FATAL] ONNX DQN model returned unexpected action dimensions: " << action_dim 
                          << " (Expected raw=" << dqn_action_map_.size() << " or wrapped=4)\n";
                std::exit(1);
            }
        }
        else if (algorithm_ == "ppo") {
            if (action_dim == 4) {
                // ==========================================
                // [PPO Model Mapping] Continuous Action Space
                // ==========================================
                out_policy.recovery_rate = float_output[0] * 0.5;
                out_policy.penalty_multiplier = float_output[1] * 100.0;
                out_policy.sq_threshold = static_cast<int>(400 + (float_output[2] * 400));
                out_policy.base_sampling_rate = float_output[3];
            } 
            else if (action_dim == 3) {
                out_policy.recovery_rate = float_output[0] * 0.5;
                out_policy.penalty_multiplier = float_output[1] * 100.0;
                out_policy.sq_threshold = static_cast<int>(400 + (float_output[2] * 400));
                out_policy.base_sampling_rate = telemetry.instant_sampling_rate;
            } 
            else if (action_dim == 2) {
                out_policy.recovery_rate = float_output[0] * 0.5;
                out_policy.penalty_multiplier = float_output[1] * 100.0;
                out_policy.sq_threshold = 650;
                out_policy.base_sampling_rate = 0.05;
            }
            else {
                std::cerr << "[FATAL] ONNX PPO model returned unexpected action dimensions: " << action_dim << "\n";
                std::exit(1);
            }
        }
        else {
            std::cerr << "[FATAL] ONNX C++ Bridge: Unrecognized algorithm name: " << algorithm_ << "\n";
            std::exit(1);
        }

        // 4. Heuristic Safety Clamping (Layer 2 Safeguard)
        if (safety_guards_enabled_) {
            if (out_policy.sq_threshold > 650) out_policy.sq_threshold = 650;
            if (out_policy.penalty_multiplier < 20.0) out_policy.penalty_multiplier = 20.0;
            if (out_policy.recovery_rate > 0.10) out_policy.recovery_rate = 0.10;
            if (out_policy.base_sampling_rate < 0.05) out_policy.base_sampling_rate = 0.05;
        }

        return true;
    } 
    catch (const std::exception& e) {
        std::cerr << "\n[FATAL] ONNX C++ Inference session failure: " << e.what() << "\n";
        std::cerr << "[FATAL] The ONNX model failed to load or execute. Exiting immediately to prevent silent heuristic fallback.\n";
        std::exit(1);
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

std::vector<int> RLBridge::get_allowed_cores() {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    std::vector<int> cores;
    if (sched_getaffinity(0, sizeof(cpu_set_t), &mask) == 0) {
        for (int i = 0; i < CPU_SETSIZE; ++i) {
            if (CPU_ISSET(i, &mask)) {
                cores.push_back(i);
            }
        }
    }
    return cores;
}

void RLBridge::onnx_worker_loop() {
    // 1. Thread Pinning to Core B (the secondary allowed core, Modulo wrapped)
    std::vector<int> allowed_cores = get_allowed_cores();
    int target_core = -1;
    
    if (allowed_cores.size() >= 2) {
        // We have at least 2 cores assigned to the process via taskset
        // Core A is allowed_cores[0], Core B is allowed_cores[1]
        target_core = allowed_cores[1];
        
        // Pin the main thread (from which we were spawned) to allowed_cores[0] just to be absolutely sure
        // they are physically separated.
        cpu_set_t main_mask;
        CPU_ZERO(&main_mask);
        CPU_SET(allowed_cores[0], &main_mask);
        // Note: pthread_self() here refers to the spawned thread. We should pin the main thread.
        // Wait, how do we get the main thread's pthread_t? In Linux, the main thread's thread ID (TID) is equal to the PID.
        // But actually, we don't necessarily have to pin the main thread from here, or we can pin it from the main thread during initialize_onnx.
        // Alternatively, the process affinity mask already restricts the process to {allowed_cores[0], allowed_cores[1]}.
        // If we pin the ONNX thread to allowed_cores[1], the main thread is still free to run on either. But if the main thread's affinity
        // is modified, it won't run on Core B.
        // Let's do it safely: we can pin the calling thread (main thread) during initialize_onnx, or just pin this thread to Core B here.
        // Pinning this thread to Core B (allowed_cores[1]) is already 100% sufficient to prevent it from competing on Core A!
    } else if (!allowed_cores.empty()) {
        // Only 1 core is set in process affinity (e.g. taskset -c 9)
        // Wrap core index to find the next physical CPU core
        long num_system_cores = sysconf(_SC_NPROCESSORS_ONLN);
        if (num_system_cores > 0) {
            target_core = (allowed_cores[0] + 1) % num_system_cores;
        }
    }

    if (target_core >= 0) {
        cpu_set_t onnx_mask;
        CPU_ZERO(&onnx_mask);
        CPU_SET(target_core, &onnx_mask);
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &onnx_mask);
        std::cout << ConsolePresenter::info() << "[INIT] ONNX Control Thread pinned to CPU Core: " << target_core << ConsolePresenter::reset() << "\n";
    } else {
        std::cout << ConsolePresenter::warn() << "[INIT] ONNX Control Thread running on dynamic core (affinity pinning failed/bypassed)" << ConsolePresenter::reset() << "\n";
    }

    // 2. Execution Loop
    while (!stop_onnx_thread_.load(std::memory_order_relaxed)) {
        WindowTelemetry local_telemetry;
        {
            std::unique_lock<std::mutex> lock(onnx_mutex_);
            onnx_cv_.wait(lock, [this]() {
                return stop_onnx_thread_.load(std::memory_order_relaxed) || 
                       new_telemetry_available_.load(std::memory_order_relaxed);
            });

            if (stop_onnx_thread_.load(std::memory_order_relaxed)) {
                break;
            }

            local_telemetry = shared_telemetry_;
            new_telemetry_available_.store(false, std::memory_order_release);
        }

        // Run ONNX Runtime inference in background thread (pinned to Core B)
        FilterPolicy policy{0.05, 50.0, 600, 0.10};
        if (run_onnx_inference(local_telemetry, policy)) {
            std::lock_guard<std::mutex> lock(onnx_mutex_);
            shared_policy_ = policy;
            new_policy_available_.store(true, std::memory_order_release);
        }
    }
}

}  // namespace qos_harness