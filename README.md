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
├── vanetza_patched/          # Hardened workspace integrating the adaptive circuit-breaker mitigation
├── inputs/
│   ├── base_packets/         # Legitimate standards-compliant CAM reference base frames
│   └── attack_vectors/
│       └── malware/          # Sandboxed toxic ASN.1 mutation variants and gold-standard POC exploits
├── outputs/
│   ├── csv_raw/
│   │   ├── unpatched/        # Separated data matrices from vulnerable stack execution loops
│   │   └── patched/          # Separated data matrices from protected state-machine loops
│   ├── plots/                # Automated publication-ready figures (Dual-Format: Raster PNG / Vector PDF)
│   │   ├── amplification/    # Absolute parsing latency comparisons and performance gain curves
│   │   └── qos/              # Latency jitter time-series, log-scale CDFs, and resilience timelines
│   └── stats/                # Automated cross-experiment dataframes and LaTeX table source codes
├── manage_build.sh           # Industrial orchestrator for incremental or clean workspace builds
├── run_experiments.sh        # Autonomous evaluation master console for multi-mode batch execution
└── tools/                    # Centralized analytics, automated plotting, and manuscript verification core
    ├── plot_engine.py        # Object-Oriented CLI orchestration entry point for unified plot generation
    ├── engine/               # Encapsulated backend processing modules providing core plotting engines
    │   ├── __init__.py       # Package namespace distribution controller exposing the public API
    │   ├── base.py           # Base abstract class managing academic styling and dual-format exporters
    │   ├── amplification.py  # Regression modeling and MTU amplification data processing node
    │   ├── qos.py            # Transient filtering, quantile extraction, and CDF processing node
    │   └── logger.py         # Standard ANSI semantic logging infrastructure
    └── analysis/             # Independent high-fidelity diagnostic tools and paper verification utilities
        ├── audit_timeline_window.py       # Fine-grained microsecond slice anomaly window auditor
        ├── calculate_structural_signal.py  # Sliding-window byte entropy and F2 frequency moment explorer
        └── audit_latex_references.py      # Crossref API automated citation validation parser

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
* `--modes "m1 m2"`: Override default execution matrix with custom target protocol simulation states
* `--rates "r1 r2"`: Override default sweep intervals with a custom whitespace-separated list of pollution floats

### Full-Scale Matrix Evaluation Examples

```bash
# Launch default 18-node comparative matrix sweep across modes (0,1,2) and rates (1%,5%,10%)
./run_experiments.sh unpatched --simulate-all

# Execute a highly optimized baseline sweep to generate absolute unattacked 0.0% references
./run_experiments.sh all --simulate-all --modes "0" --rates "0.0"

# Execute high-density custom sweep tracking unique target intervals on an isolated core index
./run_experiments.sh unpatched --simulate-all --rates "1.0 2.0 3.0 4.0 5.0" --no-filter-only --core 4

```

### Custom Independent Parameter Injections

```bash
# Arguments format: -t [total_frames] -p [pollution_rate] -m [attack_mode] [-f enable_filter]
./run_experiments.sh unpatched --custom -t 50000 -p 2.5 -m 0
./run_experiments.sh patched --custom -t 50000 -p 5.0 -m 2 -f

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

# Extract the dynamic resilience chronological timelines for pulse and flapping attack windows
python tools/plot_engine.py --type timeline

```

### Independent Telemetry & Manuscript Verification Suite

The `tools/analysis/` toolkit contains specialized utilities configured with explicit project-root anchoring to operate seamlessly from any localized relative working directory.

#### 1. Fine-Grained Anomaly Window Auditor (`audit_timeline_window.py`)

Parses execution time-series matrices within high-pollution burst boundaries to calculate empirical packet drop efficiencies and calculate strict False Positive Rates (FPR).

```bash
python tools/analysis/audit_timeline_window.py --mode 1 --rate 10.0

```

#### 2. Sliding-Window Complexity Analyzer (`calculate_structural_signal.py`)

Ingests raw binary packet payload streams to extract sliding-window information entropy and the second frequency moment ($F_2$ / SQ Signal Values), establishing structural feature thresholds for early parsing rejection.

```bash
python tools/analysis/calculate_structural_signal.py --window 64

```

#### 3. Crossref Citation Metadata Auditor (`audit_latex_references.py`)

Scans the centralized `main.tex` paper bibliography environment to query the public Crossref API registry. It matches bibliographic hashes to flag metadata drift, DOI consistency errors, or malicious LLM citation hallucinations.

```bash
python tools/analysis/audit_latex_references.py

```