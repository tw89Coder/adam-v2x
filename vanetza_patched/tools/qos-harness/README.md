# QoS harness — recursion-limit comparison workspace

This harness is built against the Vanetza revision with a parser recursion
depth limit. It exists only as a parser-hardening comparison target. It is not
the proposed ADAM mechanism and is not used for the paper's principal reported
results.

Build it from the repository root:

```bash
bash manage_build.sh patched fast
```

The harness retains compatible simulation and diagnostic interfaces so the
parser-level comparison can use the same payloads and workload schedules:

```bash
bash run_experiments.sh patched --simulate-all \
  -B -m "0" -r "10.0" -N 1000000 -l 3000
```

Do not describe results from this workspace as ADAM pre-filter results. For the
primary unpatched-parser evaluation, FSM/ONNX deployment, physical UDP testbed,
and unit tests, use `vanetza_unpatched/` and the repository-level README.
