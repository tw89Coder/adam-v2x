#ifndef PRE_FILTER_HPP
#define PRE_FILTER_HPP

#include <vector>
#include <cstdint>
#include <cstddef>

namespace vanetza {
    using ByteBuffer = std::vector<uint8_t>;
}

class AdaptiveFilterFSM {
public:
    enum class State { S0_NORMAL, S1_ELEVATED, S2_CONSTRAINED, S3_QUARANTINE };

    AdaptiveFilterFSM();
    bool process_packet(const vanetza::ByteBuffer& buf);
    State get_state() const;

private:
    double   current_budget;
    uint32_t rng_state;

    const double MAX_BUDGET         = 100.0;
    const double TAU_1              = 90.0;
    const double TAU_2              = 50.0;
    const double TAU_3              = 10.0;
    const double RECOVERY_RATE      = 0.1;
    const double PENALTY_MULTIPLIER = 10.0;
    const int    WINDOW_SIZE        = 64;

    // Normal max sum_sq = 286, Attack min sum_sq = 1336
    // Threshold at 600 gives 2x margin on both sides
    const int    SQ_THRESHOLD       = 600;

    // REMOVED: ALPHA, RISK_THRESHOLD — comparison is now pure integer

    inline uint32_t fast_rand();
    int calculate_max_sum_sq(const vanetza::ByteBuffer& buf);
};

#endif // PRE_FILTER_HPP