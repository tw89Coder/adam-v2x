/**
 * @file harness_engine.cpp
 * @brief Implementation of packet parsing execution latency benchmarks.
 * 
 * DESIGN CONTEXT & SAFETY RATIONALE:
 * This module measures the raw CPU processing time of packet buffers inside the
 * ETSI ITS parser stack (represented by RouterFuzzingContext). It measures latencies
 * using high-resolution nanosecond clock offsets and catches parser exceptions/crashes
 * (e.g. CWE-674 recursion faults) to prevent harness crash failures.
 */

#include "qos_harness/harness_engine.hpp"
#include <chrono>

namespace qos_harness {

/**
 * @brief Profiles the parser latency duration for a single packet buffer indicator.
 * 
 * @param buf Raw network byte buffer payload.
 * @return Latency duration in nanoseconds, or -1 if the parser throws an exception or crashes.
 */
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