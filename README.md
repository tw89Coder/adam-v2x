# Characterizing and Mitigating MTU-constrained Parser Workload Amplification in ASN.1-based V2X Stacks

This repository contains the source code, evaluation harness, and experimental datasets for the research paper: **"Characterizing and Mitigating MTU-constrained Parser Workload Amplification in ASN.1-based V2X Stacks."** 

## Abstract / Overview

Vehicle-to-Everything (V2X) communications rely heavily on efficient presentation-layer processing to meet stringent low-latency requirements. However, the complexity of Abstract Syntax Notation One (ASN.1) parsers, specifically those utilizing Octet Encoding Rules (OER), introduces a critical vulnerability to algorithmic complexity attacks (CWE-674). 

This project empirically demonstrates that an adversary can exploit ASN.1 structural recursion to launch asymmetric resource exhaustion attacks. Even when strictly bounded by a 1400-byte Maximum Transmission Unit (MTU) constraint, maliciously crafted payloads can induce a $24.5\times$ amplification in parser workload. This local resource exhaustion causes Head-of-Line (HoL) blocking, severely degrading the Quality of Service (QoS) for legitimate safety-critical traffic.

To address this, we evaluate a **Parser-Layer Circuit Breaker** consisting of two core components:
1. **Bounded Streaming Structural Risk Filter (B-SSRF):** A constant-memory, $\mathcal{O}(1)$ anomaly detector that utilizes the localized second frequency moment ($F_2$) to identify concentrated structural padding (e.g., repeating choice indices) without relying on semantic parsing.
2. **Probabilistic Risk Budget Finite State Machine (PRB-FSM):** A risk-aware adaptive mitigation policy that mitigates computational exposure while maintaining an extremely low baseline inspection overhead ($\sim$10%) during nominal operations.

## Key Features & Technical Contributions

* **Empirical Vulnerability Profiling:** Harness-based quantification of MTU-constrained structural amplification, demonstrating a stable linear ($\mathcal{O}(N)$) scaling of execution time for vulnerable parsers.
* **Low-Overhead Structural Detection:** The $F_2$-based `B-SSRF` accurately separates legitimate high-entropy V2X cryptography payloads from malicious low-entropy structural bombs.
* **QoS-Preserving Mitigation:** The `PRB-FSM` effectively clamps P99 tail latency, reducing worst-case packet processing delay from 0.1793 ms to 0.0320 ms under tested workloads.
* **Integrated Evaluation Framework:** A custom `qos_harness` built directly into the open-source ETSI C-ITS protocol suite ([Vanetza](https://github.com/riebl/vanetza)).

## Repository Structure

The repository integrates our custom evaluation framework with the core Vanetza protocol stack. The primary structural components are as follows:

```text
.
├── vanetza_patched/            # Vanetza protocol stack with the proposed hybrid defense
├── vanetza_unpatched/          # Baseline Vanetza protocol stack (vulnerable to CWE-674)
│   └── tools/qos-harness/      # Core contribution: The QoS Evaluation Harness
│       ├── src/                # Harness source code (traffic injection, latency tracking)
│       └── csv_data/           # Raw latency and profiling data outputs
├── final_results/              # Generated publication-quality figures (e.g., latency CDFs)
├── plot_amplification.py       # Python scripts for data visualization and regression analysis
├── main.tex                    # LaTeX source of the academic paper
└── README.md                   # This file
```

### The `qos-harness` Module
The core engineering contribution of this repository resides in the `tools/qos-harness/` directory within the Vanetza subtrees. It is a high-throughput presentation-layer emulator designed to:
1. Generate and inject standards-compliant Cooperative Awareness Messages (CAM) and Decentralized Environmental Notification Messages (DENM).
2. Interleave targeted ASN.1 OER recursion bombs at controlled adversarial load ratios (e.g., 1%, 5%, 10%).
3. Micro-benchmark the parsing pipeline to extract empirical Mean, Median, P99, and Max latency distributions.

## Getting Started / Reproducibility

### Prerequisites
The evaluation harness relies on the standard dependencies of the Vanetza protocol suite. Ensure you have the following installed on a Linux environment (Ubuntu 22.04 LTS recommended):
* CMake ($\ge$ 3.5)
* Boost ($\ge$ 1.58)
* Crypto++
* GeographicLib
* Python 3 and Pandas/Matplotlib (for data visualization)

### Building the Project
To replicate the evaluation, you must build both the unpatched and patched environments.

```bash
# 1. Build the Unpatched Baseline
cd vanetza_unpatched
mkdir build && cd build
cmake ..
make -j$(nproc)

# 2. Build the Patched (Hybrid Defense) Environment
cd ../../vanetza_patched
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### Running the QoS Harness
The `qos-harness` binary will automatically process the packet injection and output the latency metrics.

```bash
# Run the harness in the unpatched environment
./vanetza_unpatched/build/tools/qos-harness/qos-harness --attack-rate 0.10

# Run the harness in the patched environment
./vanetza_patched/build/tools/qos-harness/qos-harness --attack-rate 0.10
```

### Generating Plots
After running the harness to generate the necessary `.csv` profiles in the respective `csv_data/` directories, you can recreate the IEEE-formatted graphs using the provided Python scripts:

```bash
python3 plot_amplification.py
```
Outputs will be saved directly into the `final_results/` directory.

## Citation

If you use this repository, the `qos_harness`, or the associated dataset in your academic research, please cite our paper:

```bibtex
@article{lu2026characterizing,
  title={Characterizing and Mitigating MTU-constrained Parser Workload Amplification in ASN.1-based V2X Stacks},
  author={Lu, Yi-Hung},
  journal={TBD (Under Review)},
  year={2026}
}
```

## License & Disclaimer

This project integrates with [Vanetza](https://github.com/riebl/vanetza), which is released under the GNU Lesser General Public License (LGPL). The custom additions, including the `qos-harness` and `B-SSRF` implementation, are released under the MIT License (unless otherwise specified by institutional requirements). 

**Disclaimer:** This software is provided for academic and research purposes only. The structural payloads included in the evaluation suite are designed strictly for testing local parser resilience and should not be deployed on public or production V2X networks.
