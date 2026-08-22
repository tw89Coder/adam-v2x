#pragma once

#include <algorithm>
#include <cmath>

namespace qos_harness {
namespace workload_schedule {

inline double active_window_fraction(int mode) {
    switch (mode) {
    case 0: return 1.0;
    case 1: return 0.2;
    case 2: return 0.5;
    case 3: return 0.5;
    default: return 0.0;
    }
}

inline double active_window_rate(double global_rate_percent, int mode) {
    const double duty_cycle = active_window_fraction(mode);
    if (duty_cycle <= 0.0) return 0.0;
    return std::min(100.0, std::max(0.0, global_rate_percent / duty_cycle));
}

inline unsigned int active_window_basis_threshold(double global_rate_percent, int mode) {
    return static_cast<unsigned int>(std::lround(active_window_rate(global_rate_percent, mode) * 100.0));
}

inline bool is_active_window(int packet_id, int total_packets, int mode) {
    if (packet_id < 0 || total_packets <= 0 || packet_id >= total_packets) return false;
    switch (mode) {
    case 0:
        return true;
    case 1:
        return packet_id >= total_packets * 3 / 10 && packet_id < total_packets * 5 / 10;
    case 2: {
        const int period = std::max(1, total_packets / 10);
        return ((packet_id / period) % 2) == 1;
    }
    case 3: {
        if (packet_id < total_packets * 2 / 10) return false;
        if (packet_id < total_packets * 5 / 10) return true;
        if (packet_id < total_packets * 7 / 10) return false;
        const int period = std::max(1, total_packets / 10);
        return ((packet_id / period) % 2) == 1;
    }
    default:
        return false;
    }
}

inline bool is_malicious(unsigned int random_value, int packet_id, int total_packets,
                         double global_rate_percent, int mode) {
    return is_active_window(packet_id, total_packets, mode) &&
           (random_value % 10000U) < active_window_basis_threshold(global_rate_percent, mode);
}

} // namespace workload_schedule
} // namespace qos_harness
