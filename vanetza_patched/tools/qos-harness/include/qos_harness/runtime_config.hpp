#ifndef QOS_HARNESS_RUNTIME_CONFIG_HPP
#define QOS_HARNESS_RUNTIME_CONFIG_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace qos_harness {

struct RuntimeConfig {
    std::string algorithm = "dqn";
    std::vector<float> dqn_action_map{-0.10f, -0.05f, 0.0f, 0.05f, 0.10f};
    std::string onnx_model_path;
    uint32_t control_window_packets = 100;
    int onnx_intra_op_threads = 1;
    int onnx_inter_op_threads = 1;
    bool onnx_cpu_memory_arena = true;
    bool onnx_memory_pattern = true;
    bool onnx_parallel_execution = false;
    std::string onnx_graph_optimization = "all";
    bool diagnostics_enabled = false;
    bool diagnostics_mailbox_counters = true;
    bool diagnostics_timing = true;
    bool diagnostics_policy_changes = true;
    bool diagnostics_console_summary = true;
    bool data_plane_diagnostics_enabled = false;
    bool data_plane_filter_timing = true;
    bool data_plane_parser_timing = true;
    bool data_plane_state_residency = true;
    bool data_plane_console_summary = true;

    static RuntimeConfig load(const std::string& path);
};

}  // namespace qos_harness

#endif
