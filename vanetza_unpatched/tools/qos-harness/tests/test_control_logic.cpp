#include "qos_harness/control_logic.hpp"
#include "qos_harness/pre_filter.hpp"

#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

namespace {

struct TestPolicy {
    double recovery_rate;
    double penalty_multiplier;
    int sq_threshold;
    double base_sampling_rate;
};

int failures = 0;

void expect_true(bool condition, const std::string& message) {
    if (!condition) {
        ++failures;
        std::cerr << "[FAIL] " << message << '\n';
    }
}

void expect_near(double actual, double expected, double tolerance,
                 const std::string& message) {
    expect_true(std::abs(actual - expected) <= tolerance,
                message + " (actual=" + std::to_string(actual) +
                ", expected=" + std::to_string(expected) + ")");
}

void test_telemetry_scaling() {
    using namespace qos_harness::control_logic;
    expect_near(normalize_f2(0.0), 0.0, 1e-7, "F2 zero normalization");
    expect_near(normalize_f2(kF2Normalizer), 1.0, 1e-7, "F2 upper normalization");
    expect_near(normalize_f2(-1.0), 0.0, 1e-7, "F2 lower clamp");
    expect_near(normalize_f2(kF2Normalizer + 1.0), 1.0, 1e-7, "F2 upper clamp");

    const auto legacy = normalize_legacy_telemetry(1.5, kF2Normalizer / 2.0, -0.2);
    expect_near(legacy[0], 1.0, 1e-7, "legacy sampling upper clamp");
    expect_near(legacy[1], 0.5, 1e-7, "legacy F2 scaling");
    expect_near(legacy[2], 0.0, 1e-7, "legacy anomaly lower clamp");

    const auto extended = normalize_extended_telemetry(
        -0.1, 1.1, kF2Normalizer * 2.0, 1.2, 150.0, 99, 5000);
    for (float value : extended) {
        expect_true(value >= 0.0f && value <= 1.0f,
                    "extended telemetry remains in [0,1]");
    }
    expect_near(extended[0], 0.0, 1e-7, "base sampling lower clamp");
    expect_near(extended[1], 1.0, 1e-7, "instant sampling upper clamp");
    expect_near(extended[4], 1.0, 1e-7, "budget upper clamp");
    expect_near(extended[5], 1.0, 1e-7, "FSM state upper clamp");
    expect_near(extended[6], 1.0, 1e-7, "clean streak upper clamp");
}

void test_policy_boundaries() {
    using qos_harness::control_logic::enforce_policy_boundaries;

    TestPolicy extreme{0.5, 5.0, 900, -1.0};
    enforce_policy_boundaries(extreme, true);
    expect_near(extreme.recovery_rate, 0.10, 1e-12, "recovery upper clamp");
    expect_near(extreme.penalty_multiplier, 20.0, 1e-12, "penalty lower clamp");
    expect_true(extreme.sq_threshold == 650, "SQ threshold upper clamp");
    expect_near(extreme.base_sampling_rate, 0.70, 1e-12, "S0 sampling lower clamp");

    TestPolicy upper_sampling{0.05, 50.0, 600, 2.0};
    enforce_policy_boundaries(upper_sampling, true);
    expect_near(upper_sampling.base_sampling_rate, 0.80, 1e-12,
                "architectural S0 sampling upper clamp");

    TestPolicy boundaries{0.10, 20.0, 650, 0.80};
    enforce_policy_boundaries(boundaries, true);
    expect_near(boundaries.recovery_rate, 0.10, 1e-12, "recovery boundary preserved");
    expect_near(boundaries.penalty_multiplier, 20.0, 1e-12, "penalty boundary preserved");
    expect_true(boundaries.sq_threshold == 650, "SQ boundary preserved");
    expect_near(boundaries.base_sampling_rate, 0.80, 1e-12, "sampling boundary preserved");

    TestPolicy guards_disabled{0.5, 5.0, 900, 0.75};
    enforce_policy_boundaries(guards_disabled, false);
    expect_near(guards_disabled.recovery_rate, 0.5, 1e-12, "disabled recovery guard");
    expect_near(guards_disabled.penalty_multiplier, 5.0, 1e-12, "disabled penalty guard");
    expect_true(guards_disabled.sq_threshold == 900, "disabled SQ guard");
    expect_near(guards_disabled.base_sampling_rate, 0.75, 1e-12,
                "S0 invariant preserves in-range sampling");
}

void test_action_routing() {
    using namespace qos_harness::control_logic;
    TestPolicy policy{};

    const float ppo3[] = {0.2f, 0.3f, 0.5f};
    expect_true(decode_ppo_action(ppo3, 3, 0.76, policy), "decode 3D PPO output");
    expect_near(policy.recovery_rate, 0.10, 1e-6, "3D recovery mapping");
    expect_near(policy.penalty_multiplier, 30.0, 1e-5, "3D penalty mapping");
    expect_true(policy.sq_threshold == 600, "3D SQ mapping");
    expect_near(policy.base_sampling_rate, 0.76, 1e-12,
                "3D S0 sampling uses current telemetry");

    const float ppo4[] = {0.1f, 0.4f, 0.625f, 0.78f};
    expect_true(decode_ppo_action(ppo4, 4, 0.72, policy), "decode 4D PPO output");
    expect_near(policy.base_sampling_rate, 0.78, 1e-6, "4D explicit S0 sampling");
    expect_true(!decode_ppo_action(ppo4, 2, 0.72, policy), "reject invalid PPO dimension");

    const float q_values[] = {-1.0f, 0.2f, 2.0f, 0.3f, 0.1f};
    expect_true(decode_dqn_profile_action(q_values, 5, policy),
                "decode current 5-action DQN output");
    expect_near(policy.recovery_rate, 0.05, 1e-6, "DQN profile recovery routing");
    expect_near(policy.base_sampling_rate, 0.75, 1e-6, "DQN profile sampling routing");
    expect_true(!decode_dqn_profile_action(q_values, 4, policy),
                "reject invalid DQN dimension");
}

void test_fsm_boundaries_and_f2() {
    AdaptiveFilterFSM filter;
    using State = AdaptiveFilterFSM::State;

    filter.current_budget = 100.0;
    expect_true(filter.get_state() == State::S0_NORMAL, "budget 100 maps to S0");
    filter.current_budget = 70.0;
    expect_true(filter.get_state() == State::S1_ELEVATED, "budget 70 maps to S1");
    filter.current_budget = 40.0;
    expect_true(filter.get_state() == State::S2_CONSTRAINED, "budget 40 maps to S2");
    filter.current_budget = 10.0;
    expect_true(filter.get_state() == State::S3_QUARANTINE, "budget 10 maps to S3");

    filter.set_execution_mode(AdaptiveFilterFSM::FilterExecutionMode::STATIC_FIXED_RATE);
    filter.update_policy_params(0.05, 50.0, 10000, 1.0);

    vanetza::ByteBuffer repeated(64, 0x7f);
    expect_true(!filter.process_packet(repeated), "high test threshold keeps packet benign");
    expect_true(filter.was_inspected(), "static 100 percent path inspects packet");
    expect_true(filter.get_last_sq() == 4096, "F2 repeated-byte window equals 64 squared");

    vanetza::ByteBuffer unique(64);
    for (std::size_t i = 0; i < unique.size(); ++i) unique[i] = static_cast<uint8_t>(i + 1);
    filter.process_packet(unique);
    expect_true(filter.get_last_sq() == 64, "F2 unique-byte window equals 64");

    vanetza::ByteBuffer zeros(64, 0x00);
    filter.process_packet(zeros);
    expect_true(filter.get_last_sq() == 0, "zero padding is excluded from F2");

    vanetza::ByteBuffer short_packet(63, 0x7f);
    filter.process_packet(short_packet);
    expect_true(!filter.was_inspected(), "sub-window packet takes bounded early exit");
    expect_true(filter.get_last_sq() == 0, "sub-window packet has zero F2 score");
}

}  // namespace

int main() {
    test_telemetry_scaling();
    test_policy_boundaries();
    test_action_routing();
    test_fsm_boundaries_and_f2();

    if (failures != 0) {
        std::cerr << "[FAILED] " << failures << " assertion(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "[PASSED] telemetry, policy, action-routing, F2, and FSM boundary tests\n";
    return EXIT_SUCCESS;
}
