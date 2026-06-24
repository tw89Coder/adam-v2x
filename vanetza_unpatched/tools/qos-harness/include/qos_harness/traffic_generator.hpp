#ifndef QOS_HARNESS_TRAFFIC_GENERATOR_HPP
#define QOS_HARNESS_TRAFFIC_GENERATOR_HPP

#include "qos_harness/router_fuzzing_context.hpp"
#include <vector>
#include <string>
#include <functional>
#include <utility>

namespace qos_harness {

using FloodStrategy = std::function<vanetza::ByteBuffer(size_t)>;

class TrafficGenerator {
public:
    /**
     * @brief Mutates the payload region of a base exploit packet using a randomized seed.
     * Preserves the critical ASN.1 header (bytes 0-63) intact.
     */
    static vanetza::ByteBuffer craftAttackPacket(const vanetza::ByteBuffer& poc_packet, unsigned int seed);

    /**
     * @brief Composes and returns the list of available ASN.1 workload amplification strategies.
     */
    static std::vector<std::pair<std::string, FloodStrategy>> makeStrategies();

private:
    static vanetza::ByteBuffer floodFlat02(size_t n);
    static vanetza::ByteBuffer floodFlat03(size_t n);
    static vanetza::ByteBuffer floodFlat04(size_t n);
    static vanetza::ByteBuffer floodValidIntegers(size_t n);
    static vanetza::ByteBuffer floodLargeIntegers(size_t n);
    static vanetza::ByteBuffer floodSequenceOfIntegers(size_t n);
    static vanetza::ByteBuffer floodDeepNested(size_t n);
};

} // namespace qos_harness

#endif // QOS_HARNESS_TRAFFIC_GENERATOR_HPP