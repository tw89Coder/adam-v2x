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
#include <dirent.h>
#include <sys/stat.h>

const std::string RESET   = "\033[0m";
const std::string GREEN   = "\033[32m";
const std::string RED     = "\033[31m";
const std::string YELLOW  = "\033[33m";
const std::string BLUE    = "\033[34m";

// ================================================
// File I/O
// ================================================

vanetza::ByteBuffer readFileIntoBuffer(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return {};
    const std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    vanetza::ByteBuffer buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    return buffer;
}

bool writeBufferToFile(const std::string& filename, const vanetza::ByteBuffer& buf) {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) return false;
    file.write(reinterpret_cast<const char*>(buf.data()), buf.size());
    return file.good();
}

// ================================================
// Dataset folder scanning
// ================================================

std::vector<vanetza::ByteBuffer> loadPacketsFromFolder(const std::string& folder) {
    std::vector<vanetza::ByteBuffer> packets;
    DIR* dir = opendir(folder.c_str());
    if (!dir) return packets;

    struct dirent* entry;
    std::vector<std::string> filenames;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;
        filenames.push_back(folder + "/" + name);
    }
    closedir(dir);

    std::sort(filenames.begin(), filenames.end());
    for (const auto& path : filenames) {
        auto buf = readFileIntoBuffer(path);
        if (!buf.empty()) {
            packets.push_back(buf);
        }
    }
    return packets;
}

// ================================================
// Attack packet generation
// Keep GeoNetworking + BTP header intact (first 16 bytes)
// so Vanetza does not reject at header parse stage
// Randomize only payload region for diversity
// ================================================

vanetza::ByteBuffer craftAttackPacket(const vanetza::ByteBuffer& poc_packet,
                                       unsigned int seed) {
    vanetza::ByteBuffer attack = poc_packet;  // start from real exploit
    srand(seed);

    // PRESERVE bytes 0-63 exactly — this is the ASN.1 header that
    // triggers Vanetza's deep certificate parsing (the exploit trigger)
    // Only mutate the flood region (byte 64 onward)
    // The flood byte in poc is 0x02 — vary it slightly so packets differ
    // but still cause deep stack allocation

    if (attack.size() <= 64) return attack;

    // Pick a flood byte close to 0x02 — stays in ASN.1 integer tag range
    // so Vanetza keeps parsing deeply instead of rejecting early
    const uint8_t flood_candidates[] = {0x02, 0x01, 0x03, 0x04};
    uint8_t flood_byte = flood_candidates[rand() % 4];

    // Vary flood length slightly — keep it large enough to stress the parser
    // poc is 353 bytes total, flood starts at 64, so flood length = 289
    // vary by ±20 bytes so packet sizes differ
    int variation = (rand() % 41) - 20;  // -20 to +20
    size_t flood_end = attack.size() + variation;

    // Resize if making longer
    if (flood_end > attack.size()) {
        attack.resize(flood_end, flood_byte);
    }

    // Fill flood region with chosen byte
    for (size_t i = 64; i < std::min(flood_end, attack.size()); ++i) {
        attack[i] = flood_byte;
    }

    return attack;
}

// ================================================
// Validate packet through Vanetza & Measure Latency
// Returns the latency in nanoseconds. Returns -1 if it crashes/throws.
// ================================================

long long measurePacketLatency(const vanetza::ByteBuffer& buf) {
    try {
        vanetza::RouterFuzzingContext ctx;
        vanetza::ByteBuffer copy = buf;
        
        auto start = std::chrono::high_resolution_clock::now();
        ctx.indicate(std::move(copy));
        auto end = std::chrono::high_resolution_clock::now();
        
        return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    } catch (...) {
        return -1; // Parse error or crash
    }
}

// ================================================
// Dataset builder
// Generates N_TARGET validated attack variants
// Saves to folder so they can be reused across runs
// ================================================

const int    DATASET_TARGET   = 1000;
const int    MAX_ATTEMPTS     = 100000;
const size_t HEADER_SAFE_ZONE = 16;
const std::string NORMAL_FOLDER = "input";
const std::string ATTACK_FOLDER = "input-malware";

bool buildAttackDataset(const vanetza::ByteBuffer& base_normal,
                        const vanetza::ByteBuffer& poc_packet) { 
    mkdir(ATTACK_FOLDER.c_str(), 0755);

    std::cout << "[*] Profiling base POC packet latency baseline...\n";
    long long poc_total_ns = 0;
    int profile_runs = 10;
    for (int i = 0; i < profile_runs; ++i) {
        long long lat = measurePacketLatency(poc_packet);
        if (lat < 0) {
            std::cerr << "[-] Error: Base POC packet crashed during profiling.\n";
            return false;
        }
        poc_total_ns += lat;
    }
    long long poc_mean_ns = poc_total_ns / profile_runs;
    long long latency_threshold = static_cast<long long>(poc_mean_ns * 0.9); 

    std::cout << "[+] Base POC Mean Latency: " << poc_mean_ns << " ns\n";
    std::cout << "[*] Performance Threshold set to: " << latency_threshold << " ns\n";
    std::cout << "[*] Building attack dataset (Target: " << DATASET_TARGET << " verified SLOW packets)...\n";

    int generated = 0;
    int attempts  = 0;
    int rejected  = 0;

    while (generated < DATASET_TARGET && attempts < MAX_ATTEMPTS) {
        attempts++;

        unsigned int seed = static_cast<unsigned int>(time(nullptr)) ^ (attempts * 2654435761u);
        vanetza::ByteBuffer candidate = craftAttackPacket(poc_packet, seed); 

        long long variant_latency = measurePacketLatency(candidate);

        if (variant_latency >= latency_threshold) {
            char path[256];
            snprintf(path, sizeof(path), "%s/attack_%05d.bin",
                     ATTACK_FOLDER.c_str(), generated);
            writeBufferToFile(path, candidate);
            generated++;

            if (generated % 50 == 0 || generated == DATASET_TARGET) {
                fprintf(stdout, "\r[+] Generated: %d/%d  |  Rejected: %d  |  Lat: %lld ns  ",
                        generated, DATASET_TARGET, rejected, variant_latency);
                fflush(stdout);
            }
        } else {
            rejected++;
        }
    }

    std::cout << "\n";
    if (generated < DATASET_TARGET) {
        std::cout << "[!] Warning: only generated " << generated << "/" << DATASET_TARGET
                  << " packets after " << attempts << " attempts.\n";
        return generated > 0;
    }

    std::cout << GREEN << "[+] Dataset complete: " << generated << " attack packets saved to "
              << ATTACK_FOLDER << RESET << "/\n";
    std::cout << RED << "[+] Vanetza rejection rate during generation: "
              << (rejected * 100.0 / attempts) << "%" << RESET << "\n";
    return true;
}

// ================================================
// Help
// ================================================

void printHelp(const char* progName) {
    std::cout << "Usage: " << progName << " [-t total] [-p pollution_rate] [-m mode] [-f] [--build-dataset]\n"
              << "  -t               Total packets (Default: 1000000)\n"
              << "  -p               Pollution rate 0~100 (Default: 5.0)\n"
              << "  -m               Attack Mode:\n"
              << "                     0 = Uniform Random\n"
              << "                     1 = Single Pulse (30~50% window)\n"
              << "                     2 = Periodic On-Off (5 attack waves)\n"
              << "  -f               Enable Proposed Fast Pre-Filter\n"
              << "  --build-dataset  Generate and validate attack packet dataset\n";
}

// ================================================
// Log record
// ================================================

struct LogRecord {
    int      id;
    int      is_malware;
    int      was_dropped;
    long long latency;
};

// ================================================
// Main
// ================================================

int main(int argc, char* argv[]) {
    int    total_packets  = 1000000;
    double pollution_rate = 5.0;
    int    attack_mode    = 0;
    bool   enable_filter  = false;
    bool   build_dataset  = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if      (arg == "-h")              { printHelp(argv[0]); return 0; }
        else if (arg == "--build-dataset")   build_dataset  = true;
        else if (arg == "-f")                enable_filter  = true;
        else if (arg == "-t" && i+1 < argc)  total_packets  = std::atoi(argv[++i]);
        else if (arg == "-p" && i+1 < argc)  pollution_rate = std::atof(argv[++i]);
        else if (arg == "-m" && i+1 < argc)  attack_mode    = std::atoi(argv[++i]);
    }

    // Load base normal packet
    vanetza::ByteBuffer base_normal;
    {
        auto normals = loadPacketsFromFolder(NORMAL_FOLDER);
        if (normals.empty()) {
            std::cerr << "[-] Error: No normal packets found in " << NORMAL_FOLDER << "/\n";
            return 1;
        }
        base_normal = normals[0];
        std::cout << "[*] Loaded base normal packet: " << base_normal.size() << " bytes\n";
    }

    // Load the real exploit as base for variant generation
    vanetza::ByteBuffer poc_packet = readFileIntoBuffer("input-malware/poc_mtu_limit.bin");
    if (poc_packet.empty()) {
        std::cerr << "[-] poc_mtu_limit.bin missing\n";
        return 1;
    }

    if (build_dataset) {
        // Clean old wrong variants first
        bool ok = buildAttackDataset(base_normal, poc_packet);
        return ok ? 0 : 1;
    }

    // ---- Simulation mode ----

    // Load attack dataset from folder
    std::vector<vanetza::ByteBuffer> attack_packets = loadPacketsFromFolder(ATTACK_FOLDER);
    if (attack_packets.empty()) {
        std::cerr << "[-] No attack packets found in " << ATTACK_FOLDER << "/\n";
        std::cerr << "[-] Run with --build-dataset first.\n";
        return 1;
    }
    std::cout << "[*] Loaded " << attack_packets.size() << " attack packet variants from "
              << ATTACK_FOLDER << "/\n";

    // Load all normal packets
    std::vector<vanetza::ByteBuffer> normal_packets = loadPacketsFromFolder(NORMAL_FOLDER);
    std::cout << "[*] Loaded " << normal_packets.size() << " normal packet variants from "
              << NORMAL_FOLDER << "/\n";

    // Pre-roll random sequence outside timing window
    std::vector<unsigned int> sequence(total_packets);
    for (int i = 0; i < total_packets; ++i) {
        sequence[i] = static_cast<unsigned int>(rand());
    }

    // Output CSV filename
    char out_filename[128];
    if (pollution_rate == 0.0) {
        snprintf(out_filename, sizeof(out_filename), "csv_data/qos_baseline.csv");
    } else if (enable_filter) {
        snprintf(out_filename, sizeof(out_filename),
                 "csv_data/qos_attack_%.1f_mode%d_filtered.csv", pollution_rate, attack_mode);
    } else {
        snprintf(out_filename, sizeof(out_filename),
                 "csv_data/qos_attack_%.1f_mode%d.csv", pollution_rate, attack_mode);
    }

    std::cout << "[*] Mode: " << attack_mode
              << " | Rate: " << pollution_rate
              << "% | Filter: " << (enable_filter ? "ON" : "OFF") << "\n";
    std::cout << "[*] Starting QoS Measurement...\n";

    AdaptiveFilterFSM filter_fsm;
    vanetza::RouterFuzzingContext context;
    mkdir("csv_data", 0755);

    int true_positives  = 0;
    int false_positives = 0;
    int true_negatives  = 0;
    int false_negatives = 0;

    int mode1_start  = total_packets * 0.3;
    int mode1_end    = total_packets * 0.5;
    int mode2_period = total_packets / 10;

    std::vector<LogRecord> logs;
    logs.reserve(total_packets);

    // Progress tracking
    int    print_interval  = total_packets / 20;   // print every 5%
    int    malware_so_far  = 0;

    for (int i = 0; i < total_packets; ++i) {

        // Progress print
        if (i % print_interval == 0 || i == total_packets - 1) {
            fprintf(stdout, "\r[*] Progress: %d/%d  |  Malware injected: %d  |  %.1f%%     ",
                    i, total_packets, malware_so_far,
                    100.0 * i / total_packets);
            fflush(stdout);
        }

        // Determine if this packet is malicious
        bool is_malware = false;
        if (attack_mode == 0) {
            is_malware = (sequence[i] % 100) < static_cast<unsigned int>(pollution_rate);
        } else if (attack_mode == 1) {
            if (i >= mode1_start && i <= mode1_end)
                is_malware = (sequence[i] % 100) < static_cast<unsigned int>(pollution_rate);
        } else if (attack_mode == 2) {
            int current_cycle = i / mode2_period;
            if (current_cycle % 2 == 1)
                is_malware = (sequence[i] % 100) < static_cast<unsigned int>(pollution_rate);
        }

        if (is_malware) malware_so_far++;

        // Select packet buffer from pre-validated dataset
        const vanetza::ByteBuffer& buf = is_malware
            ? attack_packets [sequence[i] % attack_packets.size()]
            : normal_packets [sequence[i] % normal_packets.size()];

        // ---- Timing window start ----
        auto start = std::chrono::high_resolution_clock::now();

        bool drop_packet = false;
        if (enable_filter) {
            drop_packet = filter_fsm.process_packet(buf);
        }

        if (drop_packet) {
            if (is_malware) true_positives++;
            else            false_positives++;
        } else {
            if (is_malware) false_negatives++;
            else            true_negatives++;

            vanetza::ByteBuffer buf_copy = buf;
            context.indicate(std::move(buf_copy));
        }

        auto end = std::chrono::high_resolution_clock::now();
        // ---- Timing window end ----

        long long latency_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
        logs.push_back({i, is_malware ? 1 : 0, drop_packet ? 1 : 0, latency_ns});

        // ── DEBUG: flag any filter spike exceeding unpatched baseline ──────
        // if (enable_filter && latency_ns > 300000) {
        //     fprintf(stderr, "[WARN] Packet %d: latency=%lldns state=%d "
        //                     "budget=%.2f streak=%d size=%zu\n",
        //             i, latency_ns, (int)filter_fsm.get_state(),
        //             filter_fsm.current_budget,
        //             filter_fsm.clean_streak,
        //             buf.size());
        // }
    }

    std::cout << "\n[*] Simulation complete. Writing data to disk...\n";

    std::ofstream csv_out(out_filename);
    csv_out << "packet_id,is_malware,was_dropped,latency_ns\n";
    for (const auto& log : logs) {
        csv_out << log.id << "," << log.is_malware << ","
                << log.was_dropped << "," << log.latency << "\n";
    }
    csv_out.close();

    if (enable_filter) {
        double total_attacks = true_positives  + false_negatives;
        double total_normal  = true_negatives  + false_positives;

        std::cout << "\n========================================\n";
        std::cout << "      FILTER FSM SECURITY REPORT\n";
        std::cout << "========================================\n";
        std::cout << "Total Packets Processed : " << total_packets           << "\n";
        std::cout << "Total Malware Injected  : " << malware_so_far          << "\n";
        std::cout << "True Positives (Blocked): " << true_positives          << " (Good!)\n";
        std::cout << "True Negatives (Passed) : " << true_negatives          << " (Good!)\n";
        std::cout << "False Positives (Dropped normal) : " << false_positives << " (BAD - Self DoS)\n";
        std::cout << "False Negatives (Missed attack)  : " << false_negatives << " (BAD - Latency Risk)\n";
        if (total_normal  > 0)
            std::cout << "False Positive Rate (FPR) : "
                      << (false_positives / total_normal)  * 100.0 << "%\n";
        if (total_attacks > 0)
            std::cout << "False Negative Rate (FNR) : "
                      << (false_negatives / total_attacks) * 100.0 << "%\n";
        std::cout << "========================================\n";
    }

    std::cout << GREEN << "[+] Saved to " << out_filename << RESET << "\n";
    return 0;
}