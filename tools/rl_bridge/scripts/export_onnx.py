#!/usr/bin/env python3
# ==============================================================================
# V2X DRL Model to ONNX Formatter Exporter
# ==============================================================================
"""
@file export_onnx.py
@brief Centralized pipeline to export PyTorch PPO Policy weights to ONNX format.

Dynamically inspects the PyTorch checkpoint weights to auto-detect the action 
dimensions and hidden layers topology, builds a matching actor model,
loads the weights, and serializes the network to the ONNX graph format.
"""

import argparse
import os
import sys
import torch
import torch.nn as nn

# Centralize paths relative to Python root tools/rl_bridge
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from src.config import RAW_CFG, ONLINE_BRAIN_PATH, C_INFO, C_SUCCESS, C_WARN, C_ERROR, C_RESET

def parse_arguments():
    parser = argparse.ArgumentParser(description="V2X DRL Actor Policy ONNX Export Pipeline")
    parser.add_argument("-m", "--model", type=str, default=None, help="Path to input PyTorch checkpoint (.pth)")
    parser.add_argument("-o", "--output", type=str, default=None, help="Path to output ONNX model (.onnx)")
    return parser.parse_args()

def main():
    args = parse_arguments()

    print(f"{C_INFO}┌──────────────────────────────────────────────────────────────┐{C_RESET}")
    print(f"{C_INFO}│          V2X DRL ACTOR POLICY ONNX EXPORT PIPELINE           │{C_RESET}")
    print(f"{C_INFO}└──────────────────────────────────────────────────────────────┘{C_RESET}")

    # Determine input checkpoint path (command-line override takes priority)
    if args.model:
        if os.path.isabs(args.model) or os.path.exists(args.model):
            checkpoint_path = args.model
        else:
            from src.config import WORKSPACE_ROOT
            checkpoint_path = os.path.join(WORKSPACE_ROOT, args.model)
    else:
        checkpoint_path = ONLINE_BRAIN_PATH

    # Determine output ONNX path
    if args.output:
        onnx_output_path = args.output
    else:
        workspace_root = os.path.dirname(os.path.dirname(PROJECT_ROOT))
        onnx_output_path = os.path.join(workspace_root, "checkpoints", "v2x_agent.onnx")

    if not os.path.exists(checkpoint_path):
        print(f"{C_ERROR}[FATAL] Target PyTorch checkpoint missing at: {os.path.abspath(checkpoint_path)}{C_RESET}")
        print(f"  └── {C_WARN}[SUGGESTION] By default, the exporter targets the online brain checkpoint.")
        print(f"      To export a specific model (e.g. offline pre-trained weights), please specify it explicitly via the -m flag.")
        
        # Scan and list available checkpoints with modified times
        checkpoint_dir = os.path.join(os.path.dirname(os.path.dirname(PROJECT_ROOT)), RAW_CFG["infrastructure"].get("checkpoint_dir", "checkpoints"))
        if os.path.exists(checkpoint_dir):
            pth_files = [f for f in os.listdir(checkpoint_dir) if f.endswith(".pth")]
            if pth_files:
                print(f"\n      {C_INFO}Available checkpoints in '{checkpoint_dir}':{C_RESET}")
                import datetime
                # Sort by modification time descending (newest first)
                pth_files_with_time = []
                for f in pth_files:
                    f_path = os.path.join(checkpoint_dir, f)
                    mtime = os.path.getmtime(f_path)
                    pth_files_with_time.append((f, mtime))
                pth_files_with_time.sort(key=lambda x: x[1], reverse=True)
                
                for f, mtime in pth_files_with_time:
                    dt = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
                    print(f"        * {f:<30} (Modified: {dt})")
                print(f"\n      {C_INFO}Usage example:{C_RESET}")
                print(f"      ./run_experiments.sh python --export-onnx -m checkpoints/{pth_files_with_time[0][0]}")
            else:
                print(f"\n      {C_INFO}(No other .pth checkpoint files found in '{checkpoint_dir}' directory){C_RESET}")
        sys.exit(1)

    # 1. Load the checkpoint weights dict to inspect the model's architecture
    try:
        checkpoint = torch.load(checkpoint_path, map_location="cpu")
    except Exception as load_err:
        print(f"{C_ERROR}[FATAL] Failed to read checkpoint weights file: {load_err}{C_RESET}")
        sys.exit(1)

    # 2. Inspect keys to dynamically auto-detect architecture specs (PPO vs. DQN)
    is_dqn = 'net.0.weight' in checkpoint
    is_ppo = 'shared_layer.0.weight' in checkpoint

    if is_dqn:
        try:
            input_dim = checkpoint['net.0.weight'].shape[1]
            hidden_dim = checkpoint['net.0.weight'].shape[0]
            action_dim = checkpoint['net.4.weight'].shape[0]
            print(f"  ├── {C_INFO}Detected DQN Model{C_RESET}     : Inputs={input_dim} | Actions={action_dim} | Hidden={hidden_dim}")
        except KeyError as key_err:
            print(f"{C_ERROR}[FATAL] DQN Checkpoint missing standard key: {key_err}{C_RESET}")
            sys.exit(1)
            
        # Determine output ONNX path if not specified
        if not args.output:
            workspace_root = os.path.dirname(os.path.dirname(PROJECT_ROOT))
            onnx_output_path = os.path.join(workspace_root, "checkpoints", "v2x_agent_dqn.onnx")
            
        # 3. Instantiate base Q-Network and load weights
        from src.models.dqn_net import DQNNet
        dqn_model = DQNNet(state_dim=input_dim, action_dim=action_dim, hidden_dim=hidden_dim)
        dqn_model.load_state_dict(checkpoint)
        dqn_model.eval()
        
        # 4. Wrap base Q-Network inside DQNDeploymentWrapper to align output signature (5 -> 4)
        class DQNDeploymentWrapper(nn.Module):
            """
            Graph-Embedded Wrapper compiling action index lookup and FSM parameters translation
            directly into PyTorch calculation graph. Allows C++ ONNX engine to see 4D outputs.
            """
            def __init__(self, dqn_net, action_map):
                super().__init__()
                self.dqn = dqn_net
                self.register_buffer("action_map_tensor", torch.tensor(action_map, dtype=torch.float32))
                
            def forward(self, full_observation):
                # full_observation shape: (batch_size, 3) where:
                # - index 0: instant_sampling_rate
                # - index 1: avg_sq
                # - index 2: anomaly_rate
                
                # 1. Forward Q-values
                q_values = self.dqn(full_observation)
                
                # 2. ArgMax greedy choice in-graph
                best_action_idx = torch.argmax(q_values, dim=1)
                
                # 3. Retrieve rate delta delta from action map buffer
                delta = self.action_map_tensor[best_action_idx]
                
                # 4. Extract current base sampling rate from telemetry index 0
                current_rate = full_observation[:, 0]
                
                # 5. Compute new rate and enforce safety boundaries in-graph
                new_rate = torch.clamp(current_rate + delta, min=0.05, max=1.0)
                
                # 6. Construct 4D output policy matching C++ expectation scaling
                batch_size = full_observation.shape[0]
                device = full_observation.device
                
                # recovery_rate: 0.05 / 0.5 = 0.1
                rec_rate = torch.full((batch_size, 1), 0.1, dtype=torch.float32, device=device)
                # penalty_multiplier: 50.0 / 100.0 = 0.5
                penalty = torch.full((batch_size, 1), 0.5, dtype=torch.float32, device=device)
                # sq_threshold: (600 - 400) / 400 = 0.5
                sq_thresh = torch.full((batch_size, 1), 0.5, dtype=torch.float32, device=device)
                # base_sampling_rate: new_rate directly
                new_rate_col = new_rate.unsqueeze(-1)
                
                return torch.cat([rec_rate, penalty, sq_thresh, new_rate_col], dim=-1)

        action_map = RAW_CFG.get("dqn", {}).get("action_map", [-0.10, -0.05, 0.0, 0.05, 0.10])
        export_model = DQNDeploymentWrapper(dqn_model, action_map)
        export_model.eval()

    elif is_ppo:
        try:
            # Input features are the second dimension of the first linear weight matrix
            input_dim = checkpoint['shared_layer.0.weight'].shape[1]
            # Hidden dimension size
            hidden_dim = checkpoint['shared_layer.0.weight'].shape[0]
            # Action space size is the first dimension of the actor head linear weight matrix
            action_dim = checkpoint['actor_head.0.weight'].shape[0]
            # Detect if model was trained with 1 or 2 shared hidden linear layers
            has_two_shared_layers = 'shared_layer.2.weight' in checkpoint
            print(f"  ├── {C_INFO}Detected PPO Model{C_RESET}     : Inputs={input_dim} | Actions={action_dim} | Double Shared Layer={has_two_shared_layers}")
        except KeyError as key_err:
            print(f"{C_ERROR}[FATAL] PPO Checkpoint missing standard key: {key_err}{C_RESET}")
            sys.exit(1)
            
        # Determine output ONNX path if not specified
        if not args.output:
            workspace_root = os.path.dirname(os.path.dirname(PROJECT_ROOT))
            onnx_output_path = os.path.join(workspace_root, "checkpoints", "v2x_agent_ppo.onnx")

        # 3. Define the Checkpoint-Adaptive Actor-Critic Network Topology
        class AdaptiveExporterModel(nn.Module):
            def __init__(self, in_dim, h_dim, out_dim, use_double_shared):
                super().__init__()
                if use_double_shared:
                    self.shared_layer = nn.Sequential(
                        nn.Linear(in_dim, h_dim),
                        nn.ReLU(),
                        nn.Linear(h_dim, h_dim),
                        nn.ReLU()
                    )
                else:
                    self.shared_layer = nn.Sequential(
                        nn.Linear(in_dim, h_dim),
                        nn.ReLU()
                    )
                self.actor_head = nn.Sequential(
                    nn.Linear(h_dim, out_dim),
                    nn.Sigmoid()
                )
                self.critic_head = nn.Linear(h_dim, 1)
                self.log_std = nn.Parameter(torch.zeros(out_dim))

        # 4. Instantiate the matching model structure and load weights
        model = AdaptiveExporterModel(input_dim, hidden_dim, action_dim, has_two_shared_layers)
        try:
            model.load_state_dict(checkpoint, strict=False)
            print(f"  ├── {C_SUCCESS}Model Struct Synced{C_RESET}  : Dynamic model structure aligned and loaded successfully.")
        except Exception as err:
            print(f"{C_ERROR}[FATAL] Mismatched state weights alignment: {err}{C_RESET}")
            sys.exit(1)

        # 5. Extract Actor sequence for ONNX export
        class ActorOnlyModel(nn.Module):
            def __init__(self, shared, actor):
                super().__init__()
                self.shared = shared
                self.actor = actor

            def forward(self, x):
                return self.actor(self.shared(x))

        export_model = ActorOnlyModel(model.shared_layer, model.actor_head)
        export_model.eval()
    else:
        print(f"{C_ERROR}[FATAL] Unrecognized model checkpoint structure. Not standard PPO or DQN model.{C_RESET}")
        sys.exit(1)

    # Create dynamic dummy input matching input features shape (Batch=1, Features=input_dim)
    dummy_input = torch.randn(1, input_dim)

    print(f"  ├── {C_INFO}Exporting Pipeline{C_RESET}      : Serializing Graph to ONNX opset 16...")
    
    try:
        os.makedirs(os.path.dirname(onnx_output_path), exist_ok=True)
        torch.onnx.export(
            export_model,
            dummy_input,
            onnx_output_path,
            export_params=True,
            opset_version=16,
            do_constant_folding=True,
            input_names=['input_telemetry'],
            output_names=['output_actions'],
            dynamic_axes={'input_telemetry': {0: 'batch_size'}, 'output_actions': {0: 'batch_size'}}
        )
        # Force the model's IR version to 9 if it exceeds the limit,
        # ensuring compatibility with older C++ ONNX Runtime libraries.
        import onnx
        onnx_model = onnx.load(onnx_output_path)
        if onnx_model.ir_version > 9:
            onnx_model.ir_version = 9
            onnx.save(onnx_model, onnx_output_path)
            print(f"  ├── {C_WARN}[NOTICE]{C_RESET}             : Overrode model IR version to 9 for C++ compatibility.")
            
        print(f"  └── {C_SUCCESS}Export Complete{C_RESET}       : Model exported successfully to:")
        print(f"      {onnx_output_path}")
    except Exception as export_err:
        print(f"{C_ERROR}[FATAL] ONNX serialization failed: {export_err}{C_RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
