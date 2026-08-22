# ADAM QoS harness — primary evaluation workspace

This C++ harness is the paper's primary receiver and simulation kernel. It is
built against the unpatched Vanetza parser so parser workload amplification can
be measured, while ADAM's bounded filter is placed before parser execution.

Use the repository-level wrappers rather than invoking build paths directly:

```bash
bash manage_build.sh unpatched fast
bash run_experiments.sh unpatched --simulate-all \
  -F -o -m "0 1 2" -r "1.0 5.0 10.0" -N 1000000 -l 3000
```

Runtime configurations include native parsing (`-B`), FSM-only filtering
(`-F`), static 100% inspection (`-F -S`), CoDel (`-C`), and ONNX DQN plus FSM
(`-F -o`). The aggregate arrival rate is fixed independently of the attack
percentage.

## Execution paths

- Local simulation generates traffic inside the C++ process.
- Online training exchanges control-window telemetry with the Python learner.
- ONNX deployment runs the frozen policy asynchronously inside the receiver.
- UDP receive mode accepts workloads from `tools/sender/udp_sender.py` for the
  physical Raspberry Pi testbed.

The publication v7 model consumes four 7-feature windows and emits five raw
Q-values. The C++ action router maps the selected profile to recovery and S0
sampling settings; FSM safety guards retain final authority.

## Tests

From the repository root:

```bash
bash run_tests.sh
```

The lightweight C++ tests cover telemetry normalization, policy clamping,
3D/4D legacy action routing, five-action raw-Q routing, F2 boundaries, and
deterministic FSM state transitions.

Run `bash run_experiments.sh --help` for the supported public workflow. The
binary's own `--help` is intended for lower-level diagnostics.
