#include "router_fuzzing_context.hpp"
#include "pre_filter.hpp"
#include <iostream>
#include <fstream>
#include <chrono>
#include <vector>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <algorithm>

vanetza::ByteBuffer readFileIntoBuffer(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return {};
    const std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    vanetza::ByteBuffer buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    return buffer;
}

void printHelp(const char* progName) {
    std::cout << "Usage: " << progName << " [-t total] [-p pollution_rate] [-m mode] [-f]\n"
              << "  -t  Total packets (Default: 1000000)\n"
              << "  -p  Pollution rate 0~100 (Default: 5.0)\n"
              << "  -m  Attack Mode:\n"
              << "        0 = Uniform Random\n"
              << "        1 = Single Pulse (30%~50% window)\n"
              << "        2 = Periodic On-Off (5 attack waves)\n"
              << "  -f  Enable Proposed Fast Pre-Filter\n";
}

int main(int argc, char* argv[]) {
    int total_packets = 1000000;
    double pollution_rate = 5.0;
    int attack_mode = 0; // Default to Mode 0
    bool enable_filter = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h") { printHelp(argv[0]); return 0; }
        else if (arg == "-t" && i + 1 < argc) total_packets = std::atoi(argv[++i]);
        else if (arg == "-p" && i + 1 < argc) pollution_rate = std::atof(argv[++i]);
        else if (arg == "-m" && i + 1 < argc) attack_mode = std::atoi(argv[++i]);
        else if (arg == "-f") enable_filter = true;
    }

    vanetza::ByteBuffer normal_packet = readFileIntoBuffer("input/cam_v3_certificate.dat");
    vanetza::ByteBuffer malware_packet = readFileIntoBuffer("input-malware/poc_mtu_limit.bin");

    if (normal_packet.empty() || malware_packet.empty()) {
        std::cerr << "[-] Error: Missing input packet files.\n";
        return 1;
    }

    vanetza::RouterFuzzingContext context;

    // Generate dynamic CSV filename to prevent overwriting
    char out_filename[128];
    if (enable_filter) {
        snprintf(out_filename, sizeof(out_filename), "csv_data/qos_attack_%.1f_mode%d_filtered.csv", pollution_rate, attack_mode);
    } else {
        snprintf(out_filename, sizeof(out_filename), "csv_data/qos_attack_%.1f_mode%d.csv", pollution_rate, attack_mode);
    }

    std::ofstream csv_out(out_filename);
    csv_out << "packet_id,is_malware,latency_ns\n";

    std::cout << "[*] Mode: " << attack_mode << " | Rate: " << pollution_rate << "% | Filter: " << (enable_filter ? "ON" : "OFF") << "\n";
    std::cout << "[*] Starting QoS Measurement...\n";
    
    AdaptiveFilterFSM filter_fsm;

    // Define Mode 1 pulse window (30% to 50% of total packets)
    int mode1_start = total_packets * 0.3;
    int mode1_end = total_packets * 0.5;

    // Define Mode 2 period length (divided into 10 intervals)
    int mode2_period = total_packets / 10; 

    for (int i = 0; i < total_packets; ++i) {
        bool is_malware = false;

        // Determine attack injection based on selected mode
        if (attack_mode == 0) {
            // Mode 0: Uniform random attack
            is_malware = (rand() % 100) < pollution_rate; 
        } 
        else if (attack_mode == 1) {
            // Mode 1: Single pulse attack
            if (i >= mode1_start && i <= mode1_end) {
                is_malware = (rand() % 100) < pollution_rate;
            }
        } 
        else if (attack_mode == 2) {
            // Mode 2: Periodic on-off attack
            int current_cycle = i / mode2_period;
            // Odd cycles are attack windows (e.g., 10%~20%, 30%~40%...)
            if (current_cycle % 2 == 1) { 
                is_malware = (rand() % 100) < pollution_rate;
            }
        }

        const vanetza::ByteBuffer& buf = is_malware ? malware_packet : normal_packet;

        auto start = std::chrono::high_resolution_clock::now();
        
        bool drop_packet = false;
        if (enable_filter) {
            drop_packet = filter_fsm.process_packet(buf);
        }
        
        if (!drop_packet) {
            vanetza::ByteBuffer buf_copy = buf;
            context.indicate(std::move(buf_copy));
        }

        auto end = std::chrono::high_resolution_clock::now();
        csv_out << i << "," << (is_malware ? 1 : 0) << "," << std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count() << "\n";
    }
    csv_out.close();

    std::cout << "[+] Saved to " << out_filename << "\n";
    return 0;
}