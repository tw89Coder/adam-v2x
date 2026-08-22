# Publication checkpoint

This directory contains only the model artifacts used by the publication's v7
DQN profile policy:

- `v2x_online_brain_dqn_cmdp_v7_profiles.pth` contains the PyTorch state
  dictionary used to reproduce the deployment export.
- `v2x_agent_dqn_cmdp_v7_profiles_raw_q.onnx` contains the ONNX computation
  graph used by the native C++ controller.
- `v2x_agent_dqn_cmdp_v7_profiles_raw_q.onnx.data` contains the external tensor
  data referenced by the ONNX graph. The `.onnx` and `.onnx.data` files form one
  deployable model and must remain together.

Verify the artifacts before evaluation:

```bash
sha256sum --check checkpoints/SHA256SUMS
```

Historical checkpoints and training telemetry are intentionally kept out of the
public source repository.
