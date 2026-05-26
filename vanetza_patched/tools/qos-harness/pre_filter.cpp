#include "pre_filter.hpp"
#include <algorithm>
#include <ctime>

AdaptiveFilterFSM::AdaptiveFilterFSM()
    : current_budget(MAX_BUDGET),
      rng_state(static_cast<uint32_t>(time(nullptr)) ^ 0xDEADBEEF)
{
}

AdaptiveFilterFSM::State AdaptiveFilterFSM::get_state() const {
    if (current_budget > TAU_1) return State::S0_NORMAL;
    if (current_budget > TAU_2) return State::S1_ELEVATED;
    if (current_budget > TAU_3) return State::S2_CONSTRAINED;
    return State::S3_QUARANTINE;
}

inline uint32_t AdaptiveFilterFSM::fast_rand() {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

int AdaptiveFilterFSM::calculate_max_sum_sq(const vanetza::ByteBuffer& buf) {
    if (buf.size() < static_cast<size_t>(WINDOW_SIZE)) return 0;

    int     histogram[256]  = {0};
    bool    in_active[256]  = {};
    uint8_t active_vals[256];
    int     n_active        = 0;
    uint8_t ring_buffer[64];
    int     ring_idx        = 0;
    int     items_in_window = 0;
    int     max_sum_sq      = 0;

    for (size_t i = 0; i < buf.size(); ++i) {
        uint8_t cur = buf[i];

        if (items_in_window == WINDOW_SIZE) {
            uint8_t old = ring_buffer[ring_idx];
            histogram[old]--;
            if (histogram[old] == 0) {
                in_active[old] = false;
                for (int j = 0; j < n_active; ++j) {
                    if (active_vals[j] == old) {
                        active_vals[j] = active_vals[--n_active];
                        break;
                    }
                }
            }
        } else {
            items_in_window++;
        }

        ring_buffer[ring_idx] = cur;
        if (!in_active[cur]) {
            in_active[cur] = true;
            active_vals[n_active++] = cur;
        }
        histogram[cur]++;
        ring_idx = (ring_idx + 1) % WINDOW_SIZE;

        if (items_in_window == WINDOW_SIZE) {
            int sum_sq = 0;
            for (int k = 0; k < n_active; ++k) {
                int c = histogram[active_vals[k]];
                sum_sq += c * c;
                if (sum_sq > SQ_THRESHOLD) return sum_sq;  // early exit
            }
            if (sum_sq > max_sum_sq) max_sum_sq = sum_sq;
        }
    }
    return max_sum_sq;
}

bool AdaptiveFilterFSM::process_packet(const vanetza::ByteBuffer& buf) {
    State state = get_state();
    bool  inspect = false;

    if (state == State::S0_NORMAL) {
        inspect = (fast_rand() % 100 < 5);
    } else if (state == State::S1_ELEVATED) {
        inspect = (fast_rand() % 100 < 50);
    } else {
        inspect = true;
    }

    bool is_anomalous = false;
    int  max_sum_sq   = 0;

    if (inspect) {
        max_sum_sq   = calculate_max_sum_sq(buf);
        is_anomalous = (max_sum_sq > SQ_THRESHOLD);
    }

    if (is_anomalous) {
        double excess = static_cast<double>(max_sum_sq - SQ_THRESHOLD) / SQ_THRESHOLD;
        current_budget = std::max(0.0, current_budget - (excess * PENALTY_MULTIPLIER * 10.0));
    } else {
        current_budget = std::min(MAX_BUDGET, current_budget + RECOVERY_RATE);
    }

    return is_anomalous;
}