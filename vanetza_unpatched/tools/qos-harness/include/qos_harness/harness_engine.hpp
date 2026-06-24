#ifndef QOS_HARNESS_HARNESS_ENGINE_HPP
#define QOS_HARNESS_HARNESS_ENGINE_HPP

#include "qos_harness/router_fuzzing_context.hpp"

namespace qos_harness {

class HarnessEngine {
public:
    /**
     * @brief Core telemetry interceptor. Measures precise nanosecond processing latency 
     * of a packet through the Vanetza protocol stack decoder pipeline.
     * @return Execution time in nanoseconds, or -1 if an exception/crash occurs.
     */
    static long long measurePacketLatency(const vanetza::ByteBuffer& buf);
};

} // namespace qos_harness

#endif // QOS_HARNESS_HARNESS_ENGINE_HPP