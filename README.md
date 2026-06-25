# Characterizing and Mitigating MTU-constrained Parser Workload Amplification in ASN.1-based V2X Stacks

This repository contains the evaluation framework, measurement harness, and dataset core for analyzing and 
mitigating Abstract Syntax Notation One (ASN.1) structural recursion vulnerabilities (CWE-674) under 
strict Maximum Transmission Unit (MTU) barriers in Vehicle-to-Everything (V2X) protocol deployments.

---

## 1. Technical Framework Architecture

The framework is structured as a decoupled presentation-layer analytics sandbox integrated directly into 
the open-source ETSI C-ITS protocol suite (Vanetza). It establishes a strict boundary between core 
parsing algorithms, automated matrix evaluation workflows, and the modular analytics suites.

```text
.
├── vanetza_unpatched/        # Baseline workspace vulnerable to CPU workload amplification (CWE-674)
│   └── tools/qos-harness/
│       ├── include/qos_harness/
│       │   ├── pre_filter.hpp  # Discrete state-machine and policy update setters
│       │   └── rl_bridge.hpp   # OOP Telemetry serialization and loopback socket managers
│       └── src/
│           ├── pre_filter.cpp  # Mathematical F2 sliding-window sketch filters
│           └── rl_bridge.cpp   # Standalone IPC handler and blocking handshake controllers
├── vanetza_patched/          # Hardened workspace integrating the adaptive circuit-breaker mitigation
├── inputs/
│   ├── base_packets/         # Legitimate standards-compliant CAM reference base frames
│   └── attack_vectors/
│       └── malware/          # Sandboxed toxic ASN.1 mutation variants and gold-standard POC exploits
├── outputs/
│   ├── csv_raw/
│   │   ├── unpatched/        # Separated data matrices from vulnerable stack execution loops
│   │   └── patched/          # Separated data matrices from protected state-machine loops
│   ├── rl_env/               # Isolated episodic DRL training trajectory traces split by pollution density
│   ├── plots/                # Automated publication-ready figures (Dual-Format: Raster PNG / Vector PDF)
│   │   ├── amplification/    # Absolute parsing latency comparisons and performance gain curves
│   │   └── qos/              # Latency jitter time-series, log-scale CDFs, and resilience timelines
│   └── stats/                # Automated cross-experiment dataframes and LaTeX table source codes
├── manage_build.sh           # Industrial orchestrator for incremental or clean workspace builds
├── run_experiments.sh        # Autonomous evaluation master console for multi-mode batch execution
└── tools/                    # Centralized analytics, automated plotting, and manuscript verification core
    ├── plot_engine.py        # Object-Oriented CLI orchestration entry point for unified plot generation
    ├── engine/               # Encapsulated backend processing modules providing core plotting engines
    └── analysis/             # Independent high-fidelity diagnostic tools and paper verification utilities

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

# Interactive Training: Launch closed-loop DRL synchronization sandbox on Mode 3 (Forces Socket Handshake)
./run_experiments.sh unpatched --train-rl

```

### Automation Configuration Modifiers

Modifiers can be flexibly placed anywhere within the command-line interface sequence:

* `-c, --core <id>`: Target hardware CPU core index for taskset processor locking (Default: 9)
* `--no-filter-only`: Force `--simulate-all` batch scheduler to execute ONLY Filter=OFF evaluation steps
* `--filter-only`: Force `--simulate-all` batch scheduler to execute ONLY Filter=ON evaluation steps
* `--modes "m1 m2"`: Override default execution matrix with custom target protocol simulation states
* `--rates "r1 r2"`: Override default sweep intervals with a custom whitespace-separated list of pollution floats

### Full-Scale Matrix Evaluation Examples

```bash
# Launch default 18-node comparative matrix sweep across modes (0,1,2) and rates (1%,5%,10%)
./run_experiments.sh unpatched --simulate-all

# Launch automated DRL training session sweeping custom pollution boundaries on pinned core indices
./run_experiments.sh unpatched --train-rl --rates "5.0 10.0 20.0" --core 4

# Execute a highly optimized baseline sweep to generate absolute unattacked 0.0% references
./run_experiments.sh all --simulate-all --modes "0" --rates "0.0"

```

### Custom Independent Parameter Injections & Policy Overrides

```bash
# Arguments format: -t [total_frames] -p [pollution_rate] -m [attack_mode] [-f enable_filter] [--recovery r]
./run_experiments.sh unpatched --custom -t 50000 -p 2.5 -m 0
./run_experiments.sh unpatched --custom -t 100000 -p 5.0 -m 1 -f --recovery 0.25 --penalty 35.0 --sq-thresh 550

```

---

## 4. Data Visualization & Advanced Analytics Engine (`tools/`)

The repository integrates an industrial-grade Object-Oriented plotting and verification toolchain to streamline downstream regression analysis and automate publication-quality figure generation. All visualization figures enforce strict IEEE/ACM venue formatting standards (including Times New Roman font faces, inward tick markers, and tight layout packing).

### Unified Plotting Orchestration Core (`plot_engine.py`)

The centralized `plot_engine.py` features a deferred lazy-loading architecture to prevent heavy backend library import overhead when querying standard text menus. It manages directories dynamically and saves every generated graphic asset as a high-resolution raster **PNG** alongside a lossless vector **PDF** for LaTeX manuscript insertion.

```bash
# Execute the complete analytical pipeline suite (Generates all dataframes, charts, and tables)
python tools/plot_engine.py --all

# Isolate the amplification pipeline to compute regression metrics and refresh the LaTeX tabular code
python tools/plot_engine.py --type amp

# Render a pinpoint QoS CDF and Jitter pair targeting a specific state configuration and rate step
python tools/plot_engine.py --type qos --mode 1 --rate 10.0

```