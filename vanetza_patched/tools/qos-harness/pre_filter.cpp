#include "pre_filter.hpp"

AdaptiveFilterFSM::AdaptiveFilterFSM()
    : current_state(State::PEACE_TIME), cooldown_counter(0), total_packets_seen(0) {}

// O(N) 內部掃描引擎 (與之前相同)
bool AdaptiveFilterFSM::scan_payload(const vanetza::ByteBuffer& buf) {
    if (buf.empty()) return false;
    const int SUSPICIOUS_REPEAT_THRESHOLD = 10;
    int consecutive_count = 1;
    uint8_t current_byte = buf[0];

    for (size_t i = 1; i < buf.size(); ++i) {
        if (buf[i] == current_byte) {
            consecutive_count++;
            if (consecutive_count > SUSPICIOUS_REPEAT_THRESHOLD) return true;
        } else {
            current_byte = buf[i];
            consecutive_count = 1;
        }
    }
    return false;
}

bool AdaptiveFilterFSM::process_packet(const vanetza::ByteBuffer& buf) {
    total_packets_seen++;
    bool drop_packet = false;

    if (current_state == State::PEACE_TIME) {
        // 【和平時期】：機率抽查
        // 為了極致效能，我們不使用複雜的亂數生成器（如 MT19937），
        // 而是透過簡單的 modulo 運算來模擬 5% 的取樣率 (每 20 顆抽查 1 顆)。
        // 這樣可以保證在正常流量下，過濾器的 Overhead 逼近於 0。
        if (total_packets_seen % (100 / SAMPLING_RATE_PERCENT) == 0) {
            drop_packet = scan_payload(buf);
            
            if (drop_packet) {
                // 警報觸發！切換狀態並拉起熔斷器
                current_state = State::UNDER_ATTACK;
                cooldown_counter = COOLDOWN_MAX;
            }
        }
    } 
    else { // State::UNDER_ATTACK
        // 【受攻擊時期】：100% 嚴格掃描
        drop_packet = scan_payload(buf);
        
        if (drop_packet) {
            // 持續受到攻擊，重新填滿冷卻計數器
            cooldown_counter = COOLDOWN_MAX;
        } else {
            // 收到安全封包，計數器遞減
            cooldown_counter--;
            if (cooldown_counter <= 0) {
                // 威脅解除，系統回歸和平時期
                current_state = State::PEACE_TIME;
            }
        }
    }

    return drop_packet;
}