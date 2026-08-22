#ifndef PRE_FILTER_HPP
#define PRE_FILTER_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace vanetza {
using ByteBuffer = std::vector<uint8_t>;
}

class AdaptiveFilterFSM {
public:
    enum class State { S0_NORMAL, S1_ELEVATED, S2_CONSTRAINED, S3_QUARANTINE };
    enum class FilterExecutionMode {
        DYNAMIC_ADAPTIVE_FSM, // Dynamic PRB-FSM risk-driven sampling (5% peacetime up to 100%)
        STATIC_FIXED_RATE,    // Static non-adaptive fixed sampling (e.g. 100% static inspection)
        ONNX_INFERENCE,       // In-process DRL ONNX model policy
        RL_SOCKET_CONTROL     // Interactive socket Python RL bridge
    };

    AdaptiveFilterFSM();
    void set_random_seed(uint32_t seed) { rng_state = seed ? seed : 0xA341316CU; }
    bool process_packet(const vanetza::ByteBuffer& buf);
    State get_state() const;

    void set_execution_mode(FilterExecutionMode mode) {
        execution_mode_ = mode;
        if (mode == FilterExecutionMode::STATIC_FIXED_RATE) {
            adaptive_sampling_enabled_ = false;
        } else {
            adaptive_sampling_enabled_ = true;
        }
    }

    FilterExecutionMode get_execution_mode() const { return execution_mode_; }

    void update_policy_params(double recovery, double penalty, int sq_thresh, double base_sampling) {
        RECOVERY_RATE = recovery;
        PENALTY_MULTIPLIER = penalty;
        SQ_THRESHOLD = sq_thresh;
        BASE_SAMPLING_RATE = base_sampling;
    }

    // Online policy training must attribute each observed outcome to its action.
    // When disabled, the detector and its budget telemetry remain active, but
    // the FSM budget is not allowed to override the training policy's base sampling rate.
    void set_adaptive_sampling_enabled(bool enabled) {
        adaptive_sampling_enabled_ = enabled;
    }

    int get_last_sq() const {
        return last_max_sum_sq_;
    }

    double get_sampling_rate() const {
        if (execution_mode_ == FilterExecutionMode::STATIC_FIXED_RATE || !adaptive_sampling_enabled_) {
            return BASE_SAMPLING_RATE;
        }

        double fsm_floor = 0.05;
        if (current_budget <= TAU_2) {
            fsm_floor = 1.0;
        } else if (current_budget <= TAU_1) {
            constexpr double INV_TAU_SPAN = 1.0 / 30.0;
            double range_ratio = (current_budget - TAU_2) * INV_TAU_SPAN;
            fsm_floor = 1.0 - 0.5 * range_ratio;
        } else if (current_budget < MAX_BUDGET) {
            constexpr double INV_TAU_SPAN = 1.0 / 30.0;
            double range_ratio = (current_budget - TAU_1) * INV_TAU_SPAN;
            fsm_floor = 0.5 - (0.5 - 0.05) * range_ratio;
        }
        return std::max(BASE_SAMPLING_RATE, fsm_floor);
    }

    double get_base_sampling_rate() const { return BASE_SAMPLING_RATE; }
    int get_clean_streak() const { return clean_streak; }

    // exposed for debug logging in harness
    double current_budget;
    int clean_streak = 0;

    bool was_inspected() const { return last_inspected_; }
    uint64_t get_last_latency_ticks() const { return last_latency_ticks_; }

private:
    FilterExecutionMode execution_mode_ = FilterExecutionMode::DYNAMIC_ADAPTIVE_FSM;
    bool last_inspected_ = false;
    uint64_t last_latency_ticks_ = 0;
    uint32_t rng_state;

    const int STREAK_THRESHOLD = 1000;
    const double MAX_BUDGET = 100.0;
    const double TAU_1 = 70.0;
    const double TAU_2 = 40.0;
    const double TAU_3 = 10.0;
    const int WINDOW_SIZE = 64;

    double RECOVERY_RATE = 0.05;
    double PENALTY_MULTIPLIER = 50.0;
    int SQ_THRESHOLD = 600;
    double BASE_SAMPLING_RATE = 0.10;
    bool adaptive_sampling_enabled_ = true;
    int last_max_sum_sq_ = 0;
    // scan_limit is NOT a member — it's computed inside calculate_max_sum_sq
    // using buf.size() at call time:
    //   size_t scan_limit = std::min(buf.size(), static_cast<size_t>(WINDOW_SIZE + 16));

    inline uint32_t fast_rand();
    int calculate_max_sum_sq(const vanetza::ByteBuffer& buf);
};

#endif
