#ifndef QOS_HARNESS_DATASET_BUILDER_HPP
#define QOS_HARNESS_DATASET_BUILDER_HPP

#include <vanetza/common/byte_buffer.hpp>

namespace qos_harness {

class DatasetBuilder {
public:
    /**
     * @brief Builds a fuzzed exploit dataset using reproducible Hill-Climbing optimizations.
     * 
     * @param base_normal Reference normal packet buffer.
     * @param poc_packet Base POC recursive exploit packet.
     * @return true if successful, false otherwise.
     */
    static bool build(const vanetza::ByteBuffer& base_normal, const vanetza::ByteBuffer& poc_packet);

private:
    static vanetza::ByteBuffer optimizeSinglePacket(const vanetza::ByteBuffer& base_poc, 
                                                    unsigned int index, 
                                                    long long normal_lat, 
                                                    int generated, 
                                                    int target, 
                                                    int rejects,
                                                    long long& final_lat);
};

} // namespace qos_harness

#endif // QOS_HARNESS_DATASET_BUILDER_HPP
