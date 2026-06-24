# Characterizing and Mitigating MTU-constrained Parser Workload Amplification in ASN.1-based V2X Stacks

This repository contains the evaluation framework, measurement harness, and dataset core for analyzing and 
mitigating Abstract Syntax Notation One (ASN.1) structural recursion vulnerabilities (CWE-674) under 
strict Maximum Transmission Unit (MTU) barriers in Vehicle-to-Everything (V2X) protocol deployments.

---

## 1. Technical Framework Architecture

The framework is structured as a decoupled presentation-layer analytics sandbox integrated directly into 
the open-source ETSI C-ITS protocol suite (Vanetza). It establishes a strict boundary between core 
parsing algorithms and the industrial telemetry presentation layer.

```text
.
├── vanetza_unpatched/        # Baseline workspace vulnerable to CPU workload amplification (CWE-674)
├── vanetza_patched/          # Hardened workspace integrating the adaptive circuit-breaker mitigation
├── inputs/
│   ├── base_packets/         # Legitimate standards-compliant CAM reference base frames
│   └── attack_vectors/
│       └── malware/          # Sandboxed toxic ASN.1 mutation variants and gold-standard POC exploits
├── outputs/
│   ├── csv_raw/
│   │   ├── unpatched/        # Separated data matrices from vulnerable stack execution loops
│   │   └── patched/          # Separated data matrices from protected state-machine loops
│   └── amp_packets/          # Extracted binary payloads tracking geometric progression increments
├── manage_build.sh           # Industrial orchestrator for incremental or clean workspace builds
└── run_experiments.sh        # Autonomous evaluation master console for multi-mode batch execution

```

---

## 2. Automated Build Orchestration (`manage_build.sh`)

Compilation matrices are fully automated to bypass legacy caching faults or stale object linkage corruptions.

```bash
# Execute deep purge of historical cache objects and run a full clean CMake rebuild
./manage_build.sh unpatched clean
./manage_build.sh patched clean

# Execute high-speed parallel incremental compilation via naked make pipelines (2-second hot update)
./manage_build.sh unpatched fast
./manage_build.sh patched fast

```

---

## 3. Runtime Telemetry Console Parameters (`run_experiments.sh`)

The automated harness overrides hardcoded loops, supporting continuous hardware tracking pinned to a stable core.

### Standard Core Routine Invocations

```bash
# Delta Diagnosis: Verify asymmetric CPU expenditure contribution between flood payload maps
./run_experiments.sh unpatched --diagnose-flood

# Geometric Profiling: Sweep and extract packet-size vs CPU amplification factor metrics up to 1400B
./run_experiments.sh unpatched --profile-amp

# Dataset Generation: Run multi-sample strict validation loops to filter high-potency toxic variants
./run_experiments.sh unpatched --build-dataset

```

### Automation Configuration Modifiers

Modifiers can be flexibly placed anywhere within the command-line interface sequence:

* `-c, --core <id>`: Target hardware CPU core index for taskset processor locking (Default: 9)
* `--no-filter-only`: Force `--simulate-all` batch scheduler to execute ONLY Filter=OFF evaluation steps
* `--filter-only`: Force `--simulate-all` batch scheduler to execute ONLY Filter=ON evaluation steps
* `--rates "r1 r2"`: Override default sweep intervals with a custom whitespace-separated list of pollution floats

### Full-Scale Matrix Evaluation Examples

```bash
# Launch default 18-node comparative matrix sweep across modes (0,1,2) and rates (1%,5%,10%)
./run_experiments.sh unpatched --simulate-all

# Execute high-density custom sweep tracking unique target intervals on an isolated core index
./run_experiments.sh unpatched --simulate-all --rates "1.0 2.0 3.0 4.0 5.0" --no-filter-only --core 4

# Perform pinpoint defense validation against selected high-pollution density thresholds
./run_experiments.sh patched --simulate-all --rates "7.5 15.0" --filter-only --core 2

```

### Custom Independent Parameter Injections

```bash
# Arguments format: -t [total_frames] -p [pollution_rate] -m [attack_mode] [-f enable_filter]
./run_experiments.sh unpatched --custom -t 50000 -p 2.5 -m 0
./run_experiments.sh patched --custom -t 50000 -p 5.0 -m 2 -f

```

---

## 4. Telemetry Visualization Standards

All console outputs utilize an industrial telemetry palette mapped directly via ANSI hardware tracking sequences:

* **Muted Boundary Lines (`\033[90m`):** Isolates terminal layouts without adding visual distraction or friction.
* **Nominal Info Tracks (`\033[36m`):** Indicates standard background thread and simulation looping metrics.
* **Hardened Clear Indicators (`\033[32m`):** Verifies active defensive blocks and early recursion escape paths.
* **Critical Vulnerability Triggers (`\033[1;31m`):** Flags metrics exceeding strict SLA delay tolerances.

Raw metric telemetry log matrices are cleanly exported to `outputs/csv_raw/[target]/` for downstream regression analysis
and automated publication-quality figure plotting routines.