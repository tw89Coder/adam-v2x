#ifndef QOS_HARNESS_CONTROL_LOGIC_HPP
#define QOS_HARNESS_CONTROL_LOGIC_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

namespace qos_harness {
namespace control_logic {

constexpr double kF2Normalizer = 65025.0;
constexpr double kBudgetNormalizer = 100.0;
constexpr double kCleanStreakNormalizer = 1000.0;
constexpr double kMinDrlS0SamplingRate = 0.70;
constexpr double kMaxDrlS0SamplingRate = 0.80;

inline double clamp_unit(double value) noexcept {
    return std::max(0.0, std::min(1.0, value));
}

inline float normalize_f2(double sum_sq) noexcept {
    return static_cast<float>(clamp_unit(sum_sq / kF2Normalizer));
}

inline float normalize_rate(double rate) noexcept {
    return static_cast<float>(clamp_unit(rate));
}

inline float normalize_budget(double budget) noexcept {
    return static_cast<float>(clamp_unit(budget / kBudgetNormalizer));
}

inline float normalize_fsm_state(uint32_t state) noexcept {
    return static_cast<float>(std::min<uint32_t>(state, 3U)) / 3.0f;
}

inline float normalize_clean_streak(uint32_t streak) noexcept {
    return static_cast<float>(clamp_unit(streak / kCleanStreakNormalizer));
}

inline std::array<float, 3> normalize_legacy_telemetry(
        double instant_sampling_rate, double avg_max_sum_sq,
        double anomaly_rate) noexcept {
    return {{normalize_rate(instant_sampling_rate),
             normalize_f2(avg_max_sum_sq),
             normalize_rate(anomaly_rate)}};
}

inline std::array<float, 7> normalize_extended_telemetry(
        double base_sampling_rate, double instant_sampling_rate,
        double avg_max_sum_sq, double anomaly_rate, double current_budget,
        uint32_t fsm_state, uint32_t clean_streak) noexcept {
    return {{normalize_rate(base_sampling_rate),
             normalize_rate(instant_sampling_rate),
             normalize_f2(avg_max_sum_sq),
             normalize_rate(anomaly_rate),
             normalize_budget(current_budget),
             normalize_fsm_state(fsm_state),
             normalize_clean_streak(clean_streak)}};
}

inline double clamp_drl_s0_sampling_rate(double rate) noexcept {
    return std::max(kMinDrlS0SamplingRate,
                    std::min(rate, kMaxDrlS0SamplingRate));
}

template<class Policy>
inline void enforce_policy_boundaries(Policy& policy, bool safety_guards) noexcept {
    if (safety_guards) {
        if (policy.sq_threshold > 650) policy.sq_threshold = 650;
        if (policy.penalty_multiplier < 20.0) policy.penalty_multiplier = 20.0;
        if (policy.recovery_rate > 0.10) policy.recovery_rate = 0.10;
        if (policy.base_sampling_rate < kMinDrlS0SamplingRate) {
            policy.base_sampling_rate = kMinDrlS0SamplingRate;
        }
    }
    policy.base_sampling_rate = clamp_drl_s0_sampling_rate(policy.base_sampling_rate);
}

template<class Policy>
inline bool decode_ppo_action(const float* output, std::size_t action_dim,
                              double instant_sampling_rate,
                              Policy& policy) noexcept {
    if (!output || (action_dim != 3 && action_dim != 4)) return false;
    policy.recovery_rate = output[0] * 0.5;
    policy.penalty_multiplier = output[1] * 100.0;
    policy.sq_threshold = static_cast<int>(400 + output[2] * 400);
    policy.base_sampling_rate = action_dim == 4
        ? static_cast<double>(output[3])
        : instant_sampling_rate;
    return true;
}

template<class Policy>
inline bool decode_dqn_profile_action(const float* output,
                                      std::size_t action_dim,
                                      Policy& policy) noexcept {
    if (!output || action_dim != 5) return false;
    std::size_t best_action = 0;
    for (std::size_t i = 1; i < action_dim; ++i) {
        if (output[i] > output[best_action]) best_action = i;
    }
    // Keep the original float profile constants used by rl_bridge.cpp so
    // extracting this routing logic does not alter deployed policy values.
    constexpr std::array<float, 5> recovery = {{0.10f, 0.075f, 0.05f, 0.025f, 0.01f}};
    constexpr std::array<float, 5> sampling = {{0.70f, 0.70f, 0.75f, 0.80f, 0.80f}};
    policy.recovery_rate = recovery[best_action];
    policy.penalty_multiplier = 50.0;
    policy.sq_threshold = 600;
    policy.base_sampling_rate = sampling[best_action];
    return true;
}

}  // namespace control_logic
}  // namespace qos_harness

#endif
