#include "qos_harness/runtime_config.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace qos_harness {
namespace {

std::string trim(const std::string& input) {
    const auto first = input.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = input.find_last_not_of(" \t\r\n");
    return input.substr(first, last - first + 1);
}

std::string scalar(std::string value) {
    value = trim(value);
    if (value.size() >= 2 && ((value.front() == '"' && value.back() == '"') ||
                              (value.front() == '\'' && value.back() == '\''))) {
        value = value.substr(1, value.size() - 2);
    }
    return value;
}

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

bool parse_bool(const std::string& value) {
    const auto normalized = lowercase(scalar(value));
    if (normalized == "true" || normalized == "yes" || normalized == "1") return true;
    if (normalized == "false" || normalized == "no" || normalized == "0") return false;
    throw std::runtime_error("expected boolean, got '" + value + "'");
}

std::vector<float> parse_float_list(const std::string& value) {
    const auto begin = value.find('[');
    const auto end = value.rfind(']');
    if (begin == std::string::npos || end == std::string::npos || end <= begin) {
        throw std::runtime_error("expected inline numeric list");
    }
    std::vector<float> result;
    std::stringstream stream(value.substr(begin + 1, end - begin - 1));
    std::string token;
    while (std::getline(stream, token, ',')) {
        token = trim(token);
        if (!token.empty()) result.push_back(std::stof(token));
    }
    if (result.empty()) throw std::runtime_error("numeric list must not be empty");
    return result;
}

std::string without_comment(const std::string& line) {
    bool single = false;
    bool quoted = false;
    for (std::size_t i = 0; i < line.size(); ++i) {
        if (line[i] == '\'' && !quoted) single = !single;
        else if (line[i] == '"' && !single) quoted = !quoted;
        else if (line[i] == '#' && !single && !quoted) return line.substr(0, i);
    }
    return line;
}

}  // namespace

RuntimeConfig RuntimeConfig::load(const std::string& path) {
    RuntimeConfig config;
    std::ifstream file(path);
    if (!file.is_open()) return config;

    std::vector<std::pair<int, std::string>> sections;
    std::string raw;
    unsigned line_number = 0;
    while (std::getline(file, raw)) {
        ++line_number;
        const std::string line = without_comment(raw);
        const auto first = line.find_first_not_of(" \t");
        if (first == std::string::npos || line[first] == '-') continue;
        const int indent = static_cast<int>(first);
        const auto colon = line.find(':', first);
        if (colon == std::string::npos) continue;

        while (!sections.empty() && sections.back().first >= indent) sections.pop_back();
        const std::string key = trim(line.substr(first, colon - first));
        const std::string value = trim(line.substr(colon + 1));
        if (value.empty()) {
            sections.emplace_back(indent, key);
            continue;
        }

        std::string full_key;
        for (const auto& section : sections) {
            if (!full_key.empty()) full_key += '.';
            full_key += section.second;
        }
        if (!full_key.empty()) full_key += '.';
        full_key += key;

        try {
            if (full_key == "algorithm") config.algorithm = lowercase(scalar(value));
            else if (full_key == "dqn.action_map") config.dqn_action_map = parse_float_list(value);
            else if (full_key == "deployment.onnx.model_path") config.onnx_model_path = scalar(value);
            else if (full_key == "deployment.onnx.control_window_packets") {
                const unsigned long parsed = std::stoul(scalar(value));
                if (parsed == 0) throw std::runtime_error("must be greater than zero");
                config.control_window_packets = static_cast<uint32_t>(parsed);
            } else if (full_key == "deployment.onnx.intra_op_threads") {
                config.onnx_intra_op_threads = std::stoi(scalar(value));
                if (config.onnx_intra_op_threads < 1) throw std::runtime_error("must be at least one");
            } else if (full_key == "deployment.onnx.inter_op_threads") {
                config.onnx_inter_op_threads = std::stoi(scalar(value));
                if (config.onnx_inter_op_threads < 1) throw std::runtime_error("must be at least one");
            } else if (full_key == "deployment.onnx.cpu_memory_arena") {
                config.onnx_cpu_memory_arena = parse_bool(value);
            } else if (full_key == "deployment.onnx.memory_pattern") {
                config.onnx_memory_pattern = parse_bool(value);
            } else if (full_key == "deployment.onnx.execution_mode") {
                const auto mode = lowercase(scalar(value));
                if (mode != "sequential" && mode != "parallel") {
                    throw std::runtime_error("expected sequential or parallel");
                }
                config.onnx_parallel_execution = (mode == "parallel");
            } else if (full_key == "deployment.onnx.graph_optimization") {
                config.onnx_graph_optimization = lowercase(scalar(value));
                if (config.onnx_graph_optimization != "disable" &&
                    config.onnx_graph_optimization != "basic" &&
                    config.onnx_graph_optimization != "extended" &&
                    config.onnx_graph_optimization != "all") {
                    throw std::runtime_error("expected disable, basic, extended, or all");
                }
            } else if (full_key == "deployment.onnx.diagnostics.enabled") {
                config.diagnostics_enabled = parse_bool(value);
            } else if (full_key == "deployment.onnx.diagnostics.mailbox_counters") {
                config.diagnostics_mailbox_counters = parse_bool(value);
            } else if (full_key == "deployment.onnx.diagnostics.timing") {
                config.diagnostics_timing = parse_bool(value);
            } else if (full_key == "deployment.onnx.diagnostics.policy_changes") {
                config.diagnostics_policy_changes = parse_bool(value);
            } else if (full_key == "deployment.onnx.diagnostics.console_summary") {
                config.diagnostics_console_summary = parse_bool(value);
            }
        } catch (const std::exception& error) {
            throw std::runtime_error(path + ":" + std::to_string(line_number) +
                                     ": invalid " + full_key + ": " + error.what());
        }
    }
    return config;
}

}  // namespace qos_harness
