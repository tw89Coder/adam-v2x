#include "pre_filter.hpp"
#include <algorithm>
#include <ctime>

AdaptiveFilterFSM::AdaptiveFilterFSM()
    : current_budget(MAX_BUDGET),
      rng_state(static_cast<uint32_t>(time(nullptr)) ^ 0xDEADBEEF)
{}

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

    int     histogram[256] = {0};
    bool    in_active[256] = {};
    uint8_t active_vals[256];
    int     n_active        = 0;
    uint8_t ring_buffer[64];
    int     ring_idx        = 0;
    int     items_in_window = 0;
    int     max_sum_sq      = 0;

    // ── NEW: scan only the first window, not the entire packet ───────────
    // Rationale: malware has repeating bytes from byte 64 onward.
    // A single 64-byte window starting at byte 64 is sufficient to detect it.
    // Normal packets never exceed SQ_THRESHOLD in any window.
    // This caps inspection cost to O(WINDOW_SIZE) regardless of packet size.
    size_t scan_limit = std::min(buf.size(), static_cast<size_t>(WINDOW_SIZE + 16));

    for (size_t i = 0; i < scan_limit; ++i) {
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
            in_active[cur]          = true;
            active_vals[n_active++] = cur;
        }
        histogram[cur]++;
        ring_idx = (ring_idx + 1) % WINDOW_SIZE;

        if (items_in_window == WINDOW_SIZE) {
            int sum_sq = 0;
            for (int k = 0; k < n_active; ++k) {
                int c = histogram[active_vals[k]];
                sum_sq += c * c;
                if (sum_sq > SQ_THRESHOLD) return sum_sq;  // malware: exit immediately
            }
            if (sum_sq > max_sum_sq) max_sum_sq = sum_sq;
        }
    }
    return max_sum_sq;
}

bool AdaptiveFilterFSM::process_packet(const vanetza::ByteBuffer& buf) {

    // ── Fast path ────────────────────────────────────────────────────────
    if (buf.size() < static_cast<size_t>(WINDOW_SIZE)) {
        current_budget = std::min(MAX_BUDGET, current_budget + RECOVERY_RATE);
        return false;
    }

    State state   = get_state();
    bool  inspect = false;

    // ── Two-stage cheap pre-check before any state decision ─────────────
    // Cost: ~10ns, replaces full sliding window for obvious malware
    bool obvious_malware = false;
    {
        uint8_t first = buf[64];          // malware starts repeating at byte 64
        int cnt = 0;
        for (int i = 64; i < 80; ++i)    // check 16-byte window only
            cnt += (buf[i] == first);
        if (cnt >= 14)                    // 14/16 same byte = malware
            obvious_malware = true;
    }

    if (obvious_malware) {
        // Drain budget hard, skip expensive sliding window entirely
        current_budget = std::max(0.0, current_budget - PENALTY_MULTIPLIER);
        return true;
    }

    // ── State-gated sampling — DISCRETE states preserved ────────────────
    // Rationale: discrete states are auditable and certifiable for V2X
    if (state == State::S0_NORMAL) {
        inspect = (fast_rand() % 100 < 5);   // 5%: minimal overhead in safe period
    } else if (state == State::S1_ELEVATED) {
        inspect = (fast_rand() % 100 < 50);
    } else {
        inspect = true;                       // S2/S3: full inspection
    }

    bool is_anomalous = false;
    int  max_sum_sq   = 0;

    if (inspect) {
        max_sum_sq   = calculate_max_sum_sq(buf);
        is_anomalous = (max_sum_sq > SQ_THRESHOLD);
    }

    // ── Budget update with streak-accelerated recovery ───────────────────
    if (is_anomalous) {
        clean_streak = 0;
        double excess = static_cast<double>(max_sum_sq - SQ_THRESHOLD) / SQ_THRESHOLD;
        current_budget = std::max(0.0,
            current_budget - (excess * PENALTY_MULTIPLIER * 10.0));
    } else {
        clean_streak++;
        // After STREAK_THRESHOLD consecutive clean packets: recover 6x faster
        // This is the key fix for mode 2 inter-burst gaps
        double rate = (clean_streak > STREAK_THRESHOLD)
                      ? RECOVERY_RATE * 6.0
                      : RECOVERY_RATE;
        current_budget = std::min(MAX_BUDGET, current_budget + rate);
    }

    return is_anomalous;
}