#include "qos_harness/rl_bridge.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <iostream>

namespace qos_harness {

RLBridge::RLBridge(const std::string& repo_root, int port)
    : repo_root_(repo_root), port_(port), socket_enabled_(false), server_fd_(-1) {}

RLBridge::~RLBridge() {
    if (server_fd_ >= 0) {
        close(server_fd_);
    }
    if (csv_file_.is_open()) {
        csv_file_.close();
    }
}

void RLBridge::initialize(bool enable_socket, double pollution_rate, int attack_mode) {
    socket_enabled_ = enable_socket;

    // Create dedicated outputs subdirectory for reinforcement learning
    std::string dir_path = repo_root_ + "/outputs/rl_env";
    mkdir(dir_path.c_str(), 0755);

    // Dynamic File Routing to prevent cross-run trace contamination ──
    char file_path[512];
    std::snprintf(file_path, sizeof(file_path), "%s/training_trace_%.1f_mode%d.csv", dir_path.c_str(), pollution_rate,
                  attack_mode);

    // Open with truncation to guarantee clean, deterministic episodic trajectories
    csv_file_.open(file_path, std::ios::out);
    write_csv_header();
}

void RLBridge::write_csv_header() {
    csv_file_.seekp(0, std::ios::end);
    if (csv_file_.tellp() == 0) {
        csv_file_ << "packet_size,max_sum_sq,current_budget,fsm_state,is_anomalous\n";
    }
}

void RLBridge::collect_packet_telemetry(size_t pkt_size, int max_sum_sq, double budget, int state, bool is_anomalous) {
    if (csv_file_.is_open()) {
        csv_file_ << pkt_size << "," << max_sum_sq << "," << budget << "," << state << "," << (is_anomalous ? 1 : 0)
                  << "\n";
    }

    // Accumulate metrics for the current control window
    window_packet_count_++;
    window_sq_sum_ += max_sum_sq;
    window_budget_sum_ += budget;
    if (is_anomalous) {
        window_malware_count_++;
    }
}

void RLBridge::check_and_sync_window(int current_packet_idx, AdaptiveFilterFSM& filter) {
    if (window_packet_count_ < CTRL_WINDOW_SIZE) return;

    WindowTelemetry telemetry{window_sq_sum_ / window_packet_count_, window_budget_sum_ / window_packet_count_,
                              static_cast<double>(window_malware_count_) / window_packet_count_};

    // Safe fallback defaults in case handshake fails
    FilterPolicy next_policy{0.05, 50.0, 600};

    if (socket_enabled_) {
        // Pass default structure expanded with baseline backup rate (10%)
        FilterPolicy next_policy{0.05, 50.0, 600, 0.10};

        if (handshake_with_agent(telemetry, next_policy)) {
            // Apply the 4-dimensional continuous control sequence via updated OOP setter
            filter.update_policy_params(next_policy.recovery_rate, next_policy.penalty_multiplier,
                                        next_policy.sq_threshold, next_policy.s0_sampling_rate);
        }
    }

    // Reset accumulators for the next execution cycle
    window_packet_count_ = 0;
    window_sq_sum_ = 0;
    window_budget_sum_ = 0;
    window_malware_count_ = 0;
}

bool RLBridge::handshake_with_agent(const WindowTelemetry& telemetry, FilterPolicy& out_policy) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port_);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    // If Python training environment isn't up, drop connection and fallback gracefully
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock);
        return false;
    }

    // Serialize window observations into plain string
    char send_buf[256];
    std::snprintf(send_buf, sizeof(send_buf), "%f,%f,%f\n", telemetry.avg_max_sum_sq, telemetry.avg_budget,
                  telemetry.anomaly_rate);
    send(sock, send_buf, std::strlen(send_buf), 0);

    // Block current execution context and wait for optimized agent parameters
    char recv_buf[256] = {0};
    int valread = read(sock, recv_buf, sizeof(recv_buf) - 1);
    close(sock);

    if (valread <= 0) return false;

    // Deserialize incoming command string into execution tokens
    std::string res(recv_buf);
    size_t pos1 = res.find(',');
    size_t pos2 = res.find(',', pos1 + 1);
    size_t pos3 = res.find(',', pos2 + 1);  // Track the newly extended 3rd comma boundary

    if (pos1 == std::string::npos || pos2 == std::string::npos || pos3 == std::string::npos) {
        return false;  // Safely discard corrupt or unaligned protocol envelopes
    }

    // Explicit substring extraction matching the wire protocol tokens
    out_policy.recovery_rate = std::stod(res.substr(0, pos1));
    out_policy.penalty_multiplier = std::stod(res.substr(pos1 + 1, pos2 - pos1 - 1));
    out_policy.sq_threshold = std::stoi(res.substr(pos2 + 1, pos3 - pos2 - 1));
    out_policy.s0_sampling_rate = std::stod(res.substr(pos3 + 1));  // Safely parse the 4th column

    return true;
}

}  // namespace qos_harness