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
 * - Aggregates packet statistics over a window of CTRL_WINDOW_SIZE (100) packets.
 * - At window boundaries, it opens a blocking TCP socket loopback connection to port 8080.
 * - Sends a serialized telemetry observation string: "avg_max_sum_sq,avg_budget,anomaly_rate\n"
 * - Blocks execution waiting for the DRL policy decision, which is received as a serialized
 *   comma-separated control string: "recovery,penalty,sq_threshold,s0_sampling_rate\n"
 * - Dynamically updates the FSM parameters with the newly received policy.
 */

#include "qos_harness/rl_bridge.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>

#include "qos_harness/console_presenter.hpp"

#ifdef USE_ONNX
#include <onnxruntime_cxx_api.h>

#include <cmath>
#include <vector>
#endif

namespace qos_harness {

namespace {
constexpr double MIN_DRL_S0_SAMPLING_RATE = 0.05;
constexpr double MAX_DRL_S0_SAMPLING_RATE = 0.80;

double clamp_drl_s0_sampling_rate(double rate) {
    return std::max(MIN_DRL_S0_SAMPLING_RATE,
                    std::min(rate, MAX_DRL_S0_SAMPLING_RATE));
}
}  // namespace

RLBridge::RLBridge(const std::string& repo_root, int port)
    : repo_root_(repo_root),
      port_(port),
      socket_enabled_(false),
      server_fd_(-1),
      onnx_enabled_(false),
      onnx_model_path_("") {}

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
    std::snprintf(file_path, sizeof(file_path), "%s/training_trace_%.1f_mode%d_%s.csv", dir_path.c_str(),
                  pollution_rate, attack_mode, suffix.c_str());
    std::snprintf(win_file_path, sizeof(win_file_path), "%s/window_trace_%.1f_mode%d_%s.csv", dir_path.c_str(),
                  pollution_rate, attack_mode, suffix.c_str());

    if (csv_file_.is_open()) csv_file_.close();
    if (enable_trace || socket_enabled_) {
        csv_file_.open(file_path, std::ios::out);
        write_csv_header();
    }

    if (window_csv_file_.is_open()) window_csv_file_.close();
    if (enable_trace || socket_enabled_) {
        window_csv_file_.open(win_file_path, std::ios::out);
        if (window_csv_file_.is_open()) {
            window_csv_file_ << "window_index,actual_inspection_rate,target_sampling_rate,attack_intensity,fpr,fnr,avg_"
                                "sq,tp,tn,fp,fn\n";
        }
    }
}

void RLBridge::initialize_onnx(bool enable_onnx, const std::string& model_path) {
    onnx_enabled_ = enable_onnx;
    onnx_model_path_ = model_path;

    if (onnx_enabled_) {
        // Fallback to default ONNX checkpoint path if no explicit path provided
        if (onnx_model_path_.empty()) {
            std::vector<std::string> candidates = {repo_root_ + "/checkpoints/v2x_agent_dqn.onnx",
                                                   repo_root_ + "/checkpoints/v2x_agent_discrete_ppo.onnx",
                                                   repo_root_ + "/checkpoints/v2x_agent_ppo.onnx",
                                                   repo_root_ + "/tools/rl_bridge/checkpoints/v2x_agent_dqn.onnx"};
            for (const auto& cand : candidates) {
                struct stat st_cand;
                if (stat(cand.c_str(), &st_cand) == 0) {
                    onnx_model_path_ = cand;
                    break;
                }
            }
        }

        // 1. Ensure the ONNX model file exists to prevent silent execution fallback
        struct stat st;
        if (stat(onnx_model_path_.c_str(), &st) != 0) {
            std::cerr << "\n[FATAL] ONNX Model file not found at path: " << onnx_model_path_ << "\n";
            std::cerr << "[FATAL] Please verify the path or export the model first.\n";
            std::exit(1);
        }

        // 2. Dynamically parse agent.yaml to read algorithm and action_map
        algorithm_ = "dqn";                                      // Default fallback
        // This checkpoint was trained with 5%/10% sampling-rate steps. Keep
        // the native raw-Q path and the legacy wrapped ONNX contract aligned.
        dqn_action_map_ = {-0.10f, -0.05f, 0.0f, 0.05f, 0.10f};  // Default fallback

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
#ifdef USE_ONNX
        std::cout << "\n[INIT] Native C++ ONNX Runtime Engine ACTIVE (USE_ONNX=1):\n"
                  << "  └── Algorithm detected: " << algorithm_ << "\n"
                  << "  └── Action space map size: " << dqn_action_map_.size() << "\n"
                  << "  └── Model path verified: " << onnx_model_path_ << "\n\n";
#else
        std::cout << "\n[INIT] Fallback Non-ONNX Mode (USE_ONNX=0 - Missing ARM C++ Library):\n"
                  << "  └── Model path requested: " << onnx_model_path_ << "\n\n";
#endif

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

void RLBridge::collect_packet_telemetry(size_t pkt_size, int max_sum_sq, double budget, int state, bool is_anomalous,
                                        bool is_malware, bool inspected, uint64_t latency_ticks) {
    if (csv_file_.is_open()) {
        // Batching Optimization: Instead of performing disk writes on every single packet (which wastes CPU cycles on
        // IO), we store the data in an in-memory buffer and batch-flush it.
        packet_buffer_.push_back({pkt_size, max_sum_sq, budget, state, is_anomalous});
        if (packet_buffer_.size() >= static_cast<size_t>(CTRL_WINDOW_SIZE)) {
            flush_telemetry_buffer();
        }
    }

    collect_onnx_runtime_telemetry(max_sum_sq, is_anomalous, is_malware,
                                   inspected, latency_ticks);
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
        policy.base_sampling_rate = clamp_drl_s0_sampling_rate(policy.base_sampling_rate);
        filter.update_policy_params(policy.recovery_rate, policy.penalty_multiplier, policy.sq_threshold,
                                    policy.base_sampling_rate);
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
            shared_telemetry_ =
                WindowTelemetry{static_cast<double>(window_sq_sum_) / total_packets, filter.get_sampling_rate(),
                                static_cast<double>(window_tp_count_ + window_fp_count_) / total_packets,
                                static_cast<double>(window_tp_count_ + window_fn_count_) / total_packets,
                                filter.get_base_sampling_rate()};
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
            next_policy.base_sampling_rate = clamp_drl_s0_sampling_rate(next_policy.base_sampling_rate);
            filter.update_policy_params(next_policy.recovery_rate, next_policy.penalty_multiplier,
                                        next_policy.sq_threshold, next_policy.base_sampling_rate);
        }
    }
    // Write window-level metrics to window CSV log
    if (window_csv_file_.is_open()) {
        double actual_insp = (total_packets > 0) ? (static_cast<double>(window_inspected_count_) / total_packets) : 0.0;
        double target_samp = filter.get_sampling_rate();
        double attack_int =
            (total_packets > 0) ? (static_cast<double>(window_tp_count_ + window_fn_count_) / total_packets) : 0.0;

        double fpr = (window_fp_count_ + window_tn_count_ > 0)
                         ? (static_cast<double>(window_fp_count_) / (window_fp_count_ + window_tn_count_))
                         : 0.0;
        double fnr = (window_tp_count_ + window_fn_count_ > 0)
                         ? (static_cast<double>(window_fn_count_) / (window_tp_count_ + window_fn_count_))
                         : 0.0;
        double avg_sq = (total_packets > 0) ? (static_cast<double>(window_sq_sum_) / total_packets) : 0.0;

        window_csv_file_ << window_idx_++ << "," << actual_insp << "," << target_samp << "," << attack_int << "," << fpr
                         << "," << fnr << "," << avg_sq << "," << window_tp_count_ << "," << window_tn_count_ << ","
                         << window_fp_count_ << "," << window_fn_count_ << "\n";
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

void RLBridge::publish_native_onnx_window(uint32_t packet_count, uint32_t anomaly_count,
                                          uint32_t true_anomaly_count, uint64_t sq_sum,
                                          AdaptiveFilterFSM& filter) {
    if (!onnx_enabled_ || packet_count == 0) return;

    // Preserve check_and_sync_window() ordering: apply the completed policy
    // before publishing the next observation and its current sampling rate.
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
        policy.base_sampling_rate = clamp_drl_s0_sampling_rate(policy.base_sampling_rate);
        filter.update_policy_params(policy.recovery_rate, policy.penalty_multiplier,
                                    policy.sq_threshold, policy.base_sampling_rate);
        new_policy_available_.store(false, std::memory_order_release);
    }

    const double denominator = static_cast<double>(packet_count);
    {
        std::lock_guard<std::mutex> lock(onnx_mutex_);
        shared_telemetry_ = WindowTelemetry{
            static_cast<double>(sq_sum) / denominator,
            filter.get_sampling_rate(),
            static_cast<double>(anomaly_count) / denominator,
            static_cast<double>(true_anomaly_count) / denominator,
            filter.get_base_sampling_rate()};
    }
    new_telemetry_available_.store(true, std::memory_order_release);
    onnx_cv_.notify_one();
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
        static Ort::SessionOptions session_options = []() {
            Ort::SessionOptions opts;
            opts.SetIntraOpNumThreads(1);
            opts.SetInterOpNumThreads(1);
            opts.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
            opts.EnableCpuMemArena();
            opts.EnableMemPattern();
            opts.SetExecutionMode(ExecutionMode::ORT_SEQUENTIAL);
            return opts;
        }();

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
        std::vector<float> current_features = {static_cast<float>(telemetry.instant_sampling_rate),
                                               static_cast<float>(telemetry.avg_max_sum_sq / 65025.0),
                                               static_cast<float>(telemetry.anomaly_rate)};

        // --- NEW: DYNAMIC DIMENSION INSPECTION ---
        static auto input_type_info = session.GetInputTypeInfo(0);
        static auto input_tensor_info = input_type_info.GetTensorTypeAndShapeInfo();
        static std::vector<int64_t> model_input_shape = input_tensor_info.GetShape();
        static int64_t model_input_dim = model_input_shape.back();  // e.g. 3 or 12

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
                std::copy(input_history_buffer_.begin() + FEATURE_DIM, input_history_buffer_.end(),
                          input_history_buffer_.begin());
                // Place new frame at the end of the history
                std::copy(current_features.begin(), current_features.end(), input_history_buffer_.end() - FEATURE_DIM);
            } else {
                input_history_buffer_ = current_features;
            }
        }

        // 3. Prepare Input Tensor (Using the contiguous flat history vector)
        std::vector<int64_t> input_shape = {1, static_cast<int64_t>(model_input_dim)};
        auto memory_info = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
        Ort::Value input_tensor =
            Ort::Value::CreateTensor<float>(memory_info, input_history_buffer_.data(), input_history_buffer_.size(),
                                            input_shape.data(), input_shape.size());

        // 2. Execute ONNX Model Inference (Synchronous feedforward pass)
        const char* input_names[] = {input_name};
        const char* output_names[] = {output_name};

        auto start_time = std::chrono::high_resolution_clock::now();

        auto output_tensors = session.Run(Ort::RunOptions{nullptr}, input_names, &input_tensor, 1, output_names, 1);

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
                float new_rate = telemetry.base_sampling_rate + delta;
                if (new_rate < 0.05f) new_rate = 0.05f;
                if (new_rate > 0.80f) new_rate = 0.80f;

                out_policy.recovery_rate = 0.05;
                out_policy.penalty_multiplier = 50.0;
                out_policy.sq_threshold = 600;
                out_policy.base_sampling_rate = new_rate;
            } else if (action_dim == 4) {
                // ==========================================
                // [Wrapped DQN Model Mapping] DQNDeploymentWrapper
                // ==========================================
                out_policy.recovery_rate = float_output[0] * 0.5;
                out_policy.penalty_multiplier = float_output[1] * 100.0;
                out_policy.sq_threshold = static_cast<int>(400 + (float_output[2] * 400));
                // Existing wrappers encode new_effective = effective + action_delta.
                // Recover that delta and apply it to the independent DRL base so an
                // FSM-forced 100% rate can never become the next permanent base.
                double observed_delta = static_cast<double>(float_output[3]) - telemetry.instant_sampling_rate;
                double closest_delta = dqn_action_map_.front();
                for (float candidate : dqn_action_map_) {
                    if (std::abs(observed_delta - candidate) < std::abs(observed_delta - closest_delta)) {
                        closest_delta = candidate;
                    }
                }
                out_policy.base_sampling_rate = telemetry.base_sampling_rate + closest_delta;
            } else {
                std::cerr << "[FATAL] ONNX DQN model returned unexpected action dimensions: " << action_dim
                          << " (Expected raw=" << dqn_action_map_.size() << " or wrapped=4)\n";
                std::exit(1);
            }
        } else if (algorithm_ == "discrete_ppo") {
            if (action_dim == 4) {
                // Deterministic categorical PPO export wrapper. The wrapper
                // embeds the probability-weighted expected action delta and
                // sampling-rate translation.
                out_policy.recovery_rate = float_output[0] * 0.5;
                out_policy.penalty_multiplier = float_output[1] * 100.0;
                out_policy.sq_threshold = static_cast<int>(400 + (float_output[2] * 400));
                const double expected_delta = static_cast<double>(float_output[3]) - telemetry.instant_sampling_rate;
                out_policy.base_sampling_rate = telemetry.base_sampling_rate + expected_delta;
            } else {
                std::cerr << "[FATAL] ONNX Discrete PPO model returned unexpected action dimensions: " << action_dim
                          << " (Expected wrapped=4)\n";
                std::exit(1);
            }
        } else if (algorithm_ == "ppo") {
            if (action_dim == 4) {
                // ==========================================
                // [PPO Model Mapping] Continuous Action Space
                // ==========================================
                out_policy.recovery_rate = float_output[0] * 0.5;
                out_policy.penalty_multiplier = float_output[1] * 100.0;
                out_policy.sq_threshold = static_cast<int>(400 + (float_output[2] * 400));
                out_policy.base_sampling_rate = float_output[3];
            } else if (action_dim == 3) {
                out_policy.recovery_rate = float_output[0] * 0.5;
                out_policy.penalty_multiplier = float_output[1] * 100.0;
                out_policy.sq_threshold = static_cast<int>(400 + (float_output[2] * 400));
                out_policy.base_sampling_rate = telemetry.instant_sampling_rate;
            } else if (action_dim == 2) {
                out_policy.recovery_rate = float_output[0] * 0.5;
                out_policy.penalty_multiplier = float_output[1] * 100.0;
                out_policy.sq_threshold = 650;
                out_policy.base_sampling_rate = 0.05;
            } else {
                std::cerr << "[FATAL] ONNX PPO model returned unexpected action dimensions: " << action_dim << "\n";
                std::exit(1);
            }
        } else {
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
        // Architectural invariant: DRL controls only the nominal S0 range.
        // Higher effective inspection rates remain exclusively FSM budget decisions.
        out_policy.base_sampling_rate = clamp_drl_s0_sampling_rate(out_policy.base_sampling_rate);

        return true;
    } catch (const std::exception& e) {
        std::cerr << "\n[FATAL] ONNX C++ Inference session failure: " << e.what() << "\n";
        std::cerr << "[FATAL] The ONNX model failed to load or execute. Exiting immediately to prevent silent "
                     "heuristic fallback.\n";
        std::exit(1);
        return false;
    }
}
#else
bool RLBridge::run_onnx_inference(const WindowTelemetry& telemetry, FilterPolicy& out_policy) {
    WindowTelemetryPayload payload;
    payload.tp_count = window_tp_count_;
    payload.tn_count = window_tn_count_;
    payload.fp_count = window_fp_count_;
    payload.fn_count = window_fn_count_;
    payload.inspected_count = window_inspected_count_;
    payload.total_sq = window_sq_sum_;
    payload.total_latency_ticks = window_latency_ticks_;
    payload.current_sampling_rate = static_cast<float>(telemetry.instant_sampling_rate);

    if (handshake_with_agent(payload, out_policy)) {
        return true;
    }
    out_policy.recovery_rate = 0.05;
    out_policy.penalty_multiplier = 50.0;
    out_policy.sq_threshold = 600;
    out_policy.base_sampling_rate = 0.10;
    return true;
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
    // pthreads inherit their creator's affinity. The receiver is already pinned
    // to the data core, so the worker must explicitly replace that inherited mask.
    if (control_core_ >= 0) {
        cpu_set_t mask;
        CPU_ZERO(&mask);
        CPU_SET(control_core_, &mask);
        const int rc = pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask);
        if (rc != 0) {
            std::cerr << ConsolePresenter::crit()
                      << "[FATAL] Failed to pin ONNX control thread to CPU " << control_core_
                      << ": " << std::strerror(rc) << ConsolePresenter::reset() << "\n";
            std::exit(EXIT_FAILURE);
        }

        cpu_set_t verified_mask;
        CPU_ZERO(&verified_mask);
        const int verify_rc = pthread_getaffinity_np(pthread_self(), sizeof(verified_mask), &verified_mask);
        if (verify_rc != 0 || !CPU_ISSET(control_core_, &verified_mask)) {
            std::cerr << ConsolePresenter::crit()
                      << "[FATAL] ONNX control thread affinity verification failed for CPU "
                      << control_core_ << ConsolePresenter::reset() << "\n";
            std::exit(EXIT_FAILURE);
        }

        std::cout << ConsolePresenter::info() << "[INIT] ONNX control thread pinned to CPU "
                  << control_core_ << " (running on CPU " << sched_getcpu() << ")"
                  << ConsolePresenter::reset() << "\n";
    } else {
        std::cout << ConsolePresenter::info()
                  << "[INIT] ONNX control thread using OS scheduler (affinity disabled)"
                  << ConsolePresenter::reset() << "\n";
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
