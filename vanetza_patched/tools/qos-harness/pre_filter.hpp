#ifndef PRE_FILTER_HPP
#define PRE_FILTER_HPP

#include <vector>
#include <cstdint>
#include <cstddef>
#include <algorithm>

namespace vanetza {
    using ByteBuffer = std::vector<uint8_t>;
}

class AdaptiveFilterFSM {
public:
    enum class State { S0_NORMAL, S1_ELEVATED, S2_CONSTRAINED, S3_QUARANTINE };

    AdaptiveFilterFSM();
    bool process_packet(const vanetza::ByteBuffer& buf);
    State get_state() const;

    // exposed for debug logging in harness
    double current_budget;
    int    clean_streak = 0;

private:
    uint32_t rng_state;

    const int    STREAK_THRESHOLD   = 1000;
    const double MAX_BUDGET         = 100.0;
    const double TAU_1              = 70.0;
    const double TAU_2              = 40.0;
    const double TAU_3              = 10.0;
    const double RECOVERY_RATE      = 0.05;
    const double PENALTY_MULTIPLIER = 50.0;
    const int    WINDOW_SIZE        = 64;
    const int    SQ_THRESHOLD       = 600;
    // scan_limit is NOT a member — it's computed inside calculate_max_sum_sq
    // using buf.size() at call time:
    //   size_t scan_limit = std::min(buf.size(), static_cast<size_t>(WINDOW_SIZE + 16));

    inline uint32_t fast_rand();
    int calculate_max_sum_sq(const vanetza::ByteBuffer& buf);
};

#endif