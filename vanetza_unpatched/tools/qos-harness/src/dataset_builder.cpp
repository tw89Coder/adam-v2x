#include "qos_harness/dataset_builder.hpp"
#include "qos_harness/harness_engine.hpp"
#include "qos_harness/traffic_generator.hpp"
#include "qos_harness/console_presenter.hpp"
#include "qos_harness/file_manager.hpp"
#include <sys/stat.h>
#include <iostream>
#include <algorithm>
#include <cstdio>

namespace qos_harness {

namespace {
const std::string ATTACK_FOLDER = "outputs/attack_vectors";
const int DATASET_TARGET = 1000;
const int MAX_ATTEMPTS = 50000;
const long long MIN_LATENCY_THRESHOLD = 200000; // 0.2 ms threshold

long long measureMedianLatency(const vanetza::ByteBuffer& pkt, int runs = 5) {
    std::vector<long long> samples;
    for (int i = 0; i < runs; ++i) {
        long long lat = HarnessEngine::measurePacketLatency(pkt);
        if (lat > 0) samples.push_back(lat);
    }
    if (samples.empty()) return 0;
    std::sort(samples.begin(), samples.end());
    return samples[samples.size() / 2];
}
}

bool DatasetBuilder::build(const vanetza::ByteBuffer& base_normal, const vanetza::ByteBuffer& poc_packet) {
    mkdir(ATTACK_FOLDER.c_str(), 0755);

    // Profile the normal packet baseline latency (using median of 5)
    long long normal_lat = measureMedianLatency(base_normal, 5);
    if (normal_lat == 0) normal_lat = 10000; // fallback to 10us

    // Profile the base POC packet latency baseline (using median of 5)
    long long base_poc_lat = measureMedianLatency(poc_packet, 5);
    if (base_poc_lat == 0) {
        std::cout << "[!] Fatal error: POC packet is invalid or unparsable.\n";
        return false;
    }

    // Display rich header with normal/POC comparison & initial amplification factors
    ConsolePresenter::printDatasetHeader(normal_lat, base_poc_lat);

    int generated = 0, attempts = 0, rejected = 0;
    long long total_confirmed_lat = 0;

    while (generated < DATASET_TARGET && attempts < MAX_ATTEMPTS) {
        attempts++;

        long long final_optimized_lat = 0;
        vanetza::ByteBuffer optimized = optimizeSinglePacket(
            poc_packet, attempts, normal_lat, generated, DATASET_TARGET, rejected, final_optimized_lat
        );

        // Mitigate OS Jitter by performing 5 validation runs and taking the median
        long long confirmed_lat = measureMedianLatency(optimized, 5);
        bool consistently_potent = (confirmed_lat >= MIN_LATENCY_THRESHOLD);

        if (consistently_potent) {
            total_confirmed_lat += confirmed_lat;

            char path[256];
            std::snprintf(path, sizeof(path), "%s/attack_%05d.bin", ATTACK_FOLDER.c_str(), generated);
            FileManager::writeBufferToFile(path, optimized);
            generated++;
        } else {
            rejected++;
        }
    }

    // Output final summary block
    if (generated > 0) {
        double avg_lat = static_cast<double>(total_confirmed_lat) / generated;
        ConsolePresenter::printDatasetCompleteSummary(generated, attempts, rejected, avg_lat, normal_lat);
    }

    return generated >= DATASET_TARGET;
}

vanetza::ByteBuffer DatasetBuilder::optimizeSinglePacket(const vanetza::ByteBuffer& base_poc, 
                                                        unsigned int index, 
                                                        long long normal_lat, 
                                                        int generated, 
                                                        int target, 
                                                        int rejects,
                                                        long long& final_lat) {
    vanetza::ByteBuffer best_candidate = base_poc;
    long long best_lat = measureMedianLatency(best_candidate, 5);

    const int TOTAL_GENS = 100;
    for (int gen = 0; gen < TOTAL_GENS; gen++) {
        // Reproducible seeds based on fixed anchor 25519u
        unsigned int mutation_seed = 25519u ^ (index * 16777619u) ^ (gen * 2654435761u);
        vanetza::ByteBuffer mutant = TrafficGenerator::craftAttackPacket(best_candidate, mutation_seed);

        long long mutant_lat = measureMedianLatency(mutant, 5);

        if (mutant_lat > best_lat) {
            best_lat = mutant_lat;
            best_candidate = mutant;
        }

        // Print real-time climbing progress at each step (UX improvement)
        ConsolePresenter::printHillClimbStep(
            generated, target, index, gen + 1, TOTAL_GENS, best_lat, mutant_lat, normal_lat, rejects
        );
    }

    final_lat = best_lat;
    return best_candidate;
}

} // namespace qos_harness
