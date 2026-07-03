/**
 * @file file_manager.cpp
 * @brief Implementation of binary packet file I/O and directory scanning utilities.
 * 
 * DESIGN CONTEXT & UTILITIES:
 * This helper class abstracts low-level file transactions. It reads raw standard 
 * network frames from disk into memory byte buffers, writes fuzzed variant outputs,
 * and scans folders to populate baseline normal or malware attack packet datasets.
 */

#include "qos_harness/file_manager.hpp"

#include <dirent.h>
#include <sys/stat.h>

#include <algorithm>
#include <fstream>
#include <iostream>

namespace qos_harness {

/**
 * @brief Reads a binary file from disk into a ByteBuffer.
 * 
 * @param path The absolute or relative path to the file.
 * @return vanetza::ByteBuffer containing the file bytes, or empty on failure.
 */
vanetza::ByteBuffer FileManager::readFileIntoBuffer(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "[-] Error: File asset missing or inaccessible at: " << path << "\n";
        return {};
    }

    std::streamsize size = file.tellg();
    if (size <= 0) {
        std::cerr << "[-] Warning: File at " << path << " is empty.\n";
        return {};
    }

    file.seekg(0, std::ios::beg);
    vanetza::ByteBuffer buffer(size);
    if (file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return buffer;
    }
    return {};
}

/**
 * @brief Writes a ByteBuffer to disk as a binary file.
 * 
 * @param path Destination filepath.
 * @param buffer Byte buffer payload.
 * @return true if write succeeded, false otherwise.
 */
bool FileManager::writeBufferToFile(const std::string& path, const vanetza::ByteBuffer& buffer) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[-] Error: Cannot write destination payload to: " << path << "\n";
        return false;
    }
    file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    return true;
}

/**
 * @brief Scans a directory and loads all regular binary files into memory.
 * 
 * @param folder_path Folder directory to scan.
 * @return Vector of ByteBuffers representing loaded packet buffers.
 */
std::vector<vanetza::ByteBuffer> FileManager::loadPacketsFromFolder(const std::string& folder_path) {
    std::vector<vanetza::ByteBuffer> packets;
    DIR* dir = opendir(folder_path.c_str());
    if (!dir) {
        std::cerr << "[-] Warning: Target directory missing: " << folder_path << "\n";
        return packets;
    }

    struct dirent* entry;
    std::vector<std::string> files;
    
    // Read directory entries and exclude dot references
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name != "." && name != "..") {
            files.push_back(folder_path + "/" + name);
        }
    }
    closedir(dir);

    // Sort to guarantee deterministic packet loading schedules
    std::sort(files.begin(), files.end());
    struct stat st;

    for (const auto& full_path : files) {
        if (stat(full_path.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
            auto buf = readFileIntoBuffer(full_path);
            if (!buf.empty()) {
                packets.push_back(buf);
            }
        }
    }
    return packets;
}

}  // namespace qos_harness