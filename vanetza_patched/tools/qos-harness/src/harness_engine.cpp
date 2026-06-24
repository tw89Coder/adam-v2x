#include "qos_harness/harness_engine.hpp"
#include <chrono>

namespace qos_harness {

long long HarnessEngine::measurePacketLatency(const vanetza::ByteBuffer& buf) {
    try {
        vanetza::RouterFuzzingContext ctx;
        vanetza::ByteBuffer copy = buf;
        
        auto start = std::chrono::high_resolution_clock::now();
        ctx.indicate(std::move(copy));
        auto end = std::chrono::high_resolution_clock::now();
        
        return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    } catch (...) {
        return -1; // Gracefully catch presentation-layer parser crashes (CWE-674)
    }
}

} // namespace qos_harness