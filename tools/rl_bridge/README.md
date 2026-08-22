# Online policy bridge and ONNX deployment

This directory contains the Python side of ADAM's control plane: online
training, checkpoint export, and model-equivalence utilities. Python is used
during training and by the physical-testbed traffic sender; it is not on the
receiver's latency-critical packet path.

## Publication configuration

The paper uses the v7 DQN profile selector configured in `config/agent.yaml`:

- four consecutive 100-packet control windows;
- seven normalized features per window, for a 28-element model input;
- two 64-unit ReLU hidden layers;
- five raw Q-values selecting bounded `[recovery rate, S0 sampling rate]`
  profiles;
- an independent FSM that may override the selected profile.

The deployed graph and external weight data must remain together:

```text
checkpoints/v2x_agent_dqn_cmdp_v7_profiles_raw_q.onnx
checkpoints/v2x_agent_dqn_cmdp_v7_profiles_raw_q.onnx.data
```

## Online training

Run the learner and C++ harness from separate terminals:

```bash
bash run_experiments.sh python --train-online \
  --algorithm dqn \
  --checkpoint-path checkpoints/v2x_online_brain_dqn_cmdp_v7_profiles.pth
```

```bash
bash run_experiments.sh unpatched --train-rl \
  -m "0 1 2" -r "1.0 5.0 10.0" \
  -N 1000000 -l 3000 -I "1 20"
```

This closed loop trains against live C++ telemetry. Offline training remains
available for development, but it is not the paper's model-training path.

## ONNX export

The publication graph exposes raw DQN Q-values for the C++ action router:

```bash
bash run_experiments.sh python --export-onnx \
  --raw-dqn \
  -m checkpoints/v2x_online_brain_dqn_cmdp_v7_profiles.pth \
  -o checkpoints/v2x_agent_dqn_cmdp_v7_profiles_raw_q.onnx
```

Validate the exported graph before deployment:

```bash
bash run_experiments.sh python --verify-onnx \
  -o checkpoints/v2x_agent_dqn_cmdp_v7_profiles_raw_q.onnx \
  -t unpatched
```

Use `python tools/rl_bridge/src/main.py --help` and
`python tools/rl_bridge/scripts/export_onnx.py --help` for direct CLI details.

## Receiver deployment

The C++ receiver loads the ONNX graph in-process and runs inference on an
asynchronous control thread. The data-plane thread performs only bounded
structural filtering and FSM enforcement. With no explicit model path, the
receiver uses `deployment.onnx.model_path` from `config/agent.yaml`.
