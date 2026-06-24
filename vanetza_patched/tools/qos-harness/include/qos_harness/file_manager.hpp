#ifndef QOS_HARNESS_FILE_MANAGER_HPP
#define QOS_HARNESS_FILE_MANAGER_HPP

#include "qos_harness/router_fuzzing_context.hpp"
#include <string>
#include <vector>

namespace qos_harness {

class FileManager {
public:
    /**
     * @brief Reads a binary file entirely into a vanetza ByteBuffer.
     * @param filename Path to the target file.
     * @return vanetza::ByteBuffer Filled buffer, or empty if file opening fails.
     */
    static vanetza::ByteBuffer readFileIntoBuffer(const std::string& filename);

    /**
     * @brief Writes a vanetza ByteBuffer to disk as a binary file.
     * @param filename Output destination path.
     * @param buf The byte buffer data to write.
     * @return true If the write operation completed successfully.
     * @return false If file creation or write stream fails.
     */
    static bool writeBufferToFile(const std::string& filename, const vanetza::ByteBuffer& buf);

    /**
     * @brief Scans a directory and loads all valid files into a list of ByteBuffers.
     * File names are sorted alphabetically before loading.
     * @param folder Path to the target directory.
     * @return std::vector<vanetza::ByteBuffer> A collection of successfully parsed packet buffers.
     */
    static std::vector<vanetza::ByteBuffer> loadPacketsFromFolder(const std::string& folder);
};

} // namespace qos_harness

#endif // QOS_HARNESS_FILE_MANAGER_HPP