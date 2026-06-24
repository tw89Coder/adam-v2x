#ifndef QOS_HARNESS_AMPLIFICATION_PROFILER_HPP
#define QOS_HARNESS_AMPLIFICATION_PROFILER_HPP

#include "qos_harness/router_fuzzing_context.hpp"

namespace qos_harness {

class AmplificationProfiler {
public:
    /**
     * @brief Executes the full structural flood diagnostic pipeline (Variant A/B/C/D analysis).
     */
    static void runFloodDiagnosis(const vanetza::ByteBuffer& poc_packet);

    /**
     * @brief Orchestrates the geometric size progression sweep bounded under practical MTU limits.
     */
    static void runAmplificationProfiling(const vanetza::ByteBuffer& poc_packet);
};

} // namespace qos_harness

#endif // QOS_HARNESS_AMPLIFICATION_PROFILER_HPP