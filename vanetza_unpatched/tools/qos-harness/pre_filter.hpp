#ifndef PRE_FILTER_HPP
#define PRE_FILTER_HPP

#include <vector>
#include <cstdint>
#include <cstddef>

namespace vanetza {
    using ByteBuffer = std::vector<uint8_t>;
}

// ==============================================================
// [Proposed Mechanism] Adaptive Circuit Breaker FSM
// ==============================================================
class AdaptiveFilterFSM {
public:
    enum class State { PEACE_TIME, UNDER_ATTACK };

    AdaptiveFilterFSM();
    
    // 核心處理函數：回傳 true 代表惡意需丟棄，false 代表放行
    bool process_packet(const vanetza::ByteBuffer& buf);
    
    State get_state() const { return current_state; }

private:
    State current_state;
    int cooldown_counter;
    uint64_t total_packets_seen;

    // 系統參數
    const int COOLDOWN_MAX = 10000;
    const int SAMPLING_RATE_PERCENT = 5;

    // 封裝原本的 O(N) 結構頻率掃描邏輯
    bool scan_payload(const vanetza::ByteBuffer& buf);
};

#endif // PRE_FILTER_HPP