#ifndef QOS_HARNESS_SOCKET_ENGINE_HPP
#define QOS_HARNESS_SOCKET_ENGINE_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace qos_harness {

// Magic constants for UDP control handshake
constexpr uint32_t MAGIC_SESSION_START = 0x56325853; // "V2XS"
constexpr uint32_t MAGIC_SESSION_END   = 0x56325845; // "V2XE"
constexpr uint32_t MAGIC_BATCH_END     = 0x56325842; // "V2XB"

#pragma pack(push, 1)
struct UDPControlHeader {
    uint32_t magic;         // MAGIC_SESSION_START, MAGIC_SESSION_END, or MAGIC_BATCH_END
    uint32_t mode;          // Attack Mode (0, 1, 2)
    float pollution_rate;   // Pollution Rate (e.g. 10.0)
    uint32_t total_packets; // Total packets (e.g. 1000000)
    float lambda_pps;       // Arrival rate lambda (e.g. 3000.0)
    uint32_t filter_mode;   // 0 = OFF (Baseline), 1 = ADAPTIVE (FSM), 2 = STATIC100
    uint32_t is_patched;    // 0 = unpatched, 1 = patched
};
#pragma pack(pop)

class UDPSocketEngine {
public:
    /**
     * @brief Runs UDP receiver daemon on Raspberry Pi / Edge Node.
     * Listens on UDP port, handles session handshakes, processes streaming V2X frames,
     * computes M/G/1 queueing delay, and saves raw telemetry CSV.
     */
    static int run_receiver(int port, const std::string& build_type, bool no_taskset);

    /**
     * @brief Runs UDP sender on Laptop / WSL Traffic Generator.
     * Streams batch matrix sweeps over UDP at precise arrival rate lambda with session handshakes.
     */
    static int run_sender(const std::string& dest_ip, int port,
                          const std::vector<int>& modes,
                          const std::vector<double>& rates,
                          int total_packets, double lambda_pps,
                          int filter_mode, bool is_patched);
};

} // namespace qos_harness

#endif // QOS_HARNESS_SOCKET_ENGINE_HPP
