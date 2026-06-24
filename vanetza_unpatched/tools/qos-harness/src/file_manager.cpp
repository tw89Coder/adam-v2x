#include "qos_harness/file_manager.hpp"

#include <dirent.h>
#include <sys/stat.h>

#include <algorithm>
#include <fstream>
#include <iostream>

namespace qos_harness {

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

bool FileManager::writeBufferToFile(const std::string& path, const vanetza::ByteBuffer& buffer) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[-] Error: Cannot write destination payload to: " << path << "\n";
        return false;
    }
    file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    return true;
}

std::vector<vanetza::ByteBuffer> FileManager::loadPacketsFromFolder(const std::string& folder_path) {
    std::vector<vanetza::ByteBuffer> packets;
    DIR* dir = opendir(folder_path.c_str());
    if (!dir) {
        std::cerr << "[-] Warning: Target directory missing: " << folder_path << "\n";
        return packets;
    }

    struct dirent* entry;
    std::vector<std::string> files;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name != "." && name != "..") {
            files.push_back(folder_path + "/" + name);
        }
    }
    closedir(dir);

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