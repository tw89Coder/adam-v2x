# Evaluation payloads

This directory contains the nominal and recursive payloads consumed by the C++
harness and the physical-testbed UDP sender.

```text
inputs/
├── base_packets/                  # Nominal V2X payloads
├── base_packets_full.tar.gz       # Optional fast-loading nominal archive
└── attack_vectors/malware/        # Mutated recursive payloads
```

Attack vectors are syntactically valid recursive certificate-chain payloads
used to exercise ASN.1 parser workload amplification under a finite MTU. They
are evaluation artifacts, not executable malware.

The traffic schedule is independent of the payload set:

- Mode 0: attacks are uniformly distributed across the run.
- Mode 1: attacks occur in the 30%--50% single-pulse window.
- Mode 2: attacks alternate across periodic clean/attack windows.
- Mode 3: a mixed transition-heavy profile used for online training.

The configured attack rate controls the fraction of malicious payloads inside
an active attack region. The aggregate packet arrival rate remains fixed.

To add payloads, place raw nominal binaries in `base_packets/` and recursive
test binaries in `attack_vectors/malware/`. The harness and sender enumerate
regular files from these locations. Do not commit private captures or payloads
whose redistribution terms are unclear.
