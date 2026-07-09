#!/usr/bin/env python3
# ==============================================================================
# V2X QoS DRL Brain Decision Verification Audit CLI
# ==============================================================================
"""
@file verify_brain.py
@brief Diagnostic evaluation utility auditing offline policy parameters.

This script parses a path to a target brain checkpoint `.pth` file, constructs 
predefined environmental scenarios, executes forward inference passes through 
the policy network, and prints continuous parameter values mapped by the Action Adapter.
"""

import os
import sys

# CRITICAL: Structural auto-path repair to prevent local module discovery failures
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

import argparse
import torch
from typing import Any

from src.config import C_ERROR, C_RESET, C_INFO, C_WARN, MAX_PACKET_SIZE, MAX_F2_SQ
from src.envs.translators import DqnActionTranslator, PpoActionTranslator

def parse_arguments():
    """
    Sets up options for specific brain checkpoints.
    """
    parser = argparse.ArgumentParser(description="Brain Decision Verification Audit CLI")
    parser.add_argument(
        "-m", "--model", 
        type=str, 
        default=None,
        help="Path to specific target brain checkpoint asset"
    )
    parser.add_argument(
        "-a", "--algorithm",
        type=str,
        default=None,
        choices=["dqn", "ppo"],
        help="DRL algorithm selection"
    )
    return parser.parse_args()

def consult_brain(model: torch.nn.Module, translator: Any, is_dqn: bool, name: str, size: float, sq: float, anomaly: float):
    """
    Queries policy network to print model responses to predefined test cases.
    """
    curr_samp_rate = size / MAX_PACKET_SIZE
    state = torch.tensor([curr_samp_rate, sq/MAX_F2_SQ, anomaly], dtype=torch.float32)
    
    with torch.no_grad():
        if is_dqn:
            q_values = model(state.unsqueeze(0))
            action_idx = q_values.argmax(dim=-1).item()
            safe_actions = translator.translate(action_idx, curr_samp_rate)
        else:
            action_mean, _ = model(state)
            safe_actions = translator.translate(action_mean.tolist(), curr_samp_rate)
            
    # Extract mapped variables dynamically from the safe action list
    rec = safe_actions[0]
    pen = safe_actions[1]
    sq_t = safe_actions[2]
    base_samp = safe_actions[3]
    
    print(f"[{name}] Input: Size={size}B, F2_SQ={sq}, Anomaly={anomaly*100:.1f}%")
    print(f"       -> AI Action: Recovery={rec:.3f}, Penalty={pen:.1f}, SQ_Thresh={int(sq_t)}, Base_Sampling={base_samp:.3f}\n")

def main():
    args = parse_arguments()

    if args.model:
        if os.path.isabs(args.model) or os.path.exists(args.model):
            checkpoint_path = args.model
        else:
            from src.config import WORKSPACE_ROOT
            checkpoint_path = os.path.join(WORKSPACE_ROOT, args.model)
    else:
        from src.config import ONLINE_BRAIN_PATH
        checkpoint_path = ONLINE_BRAIN_PATH

    if not os.path.exists(checkpoint_path):
        from src.config import RAW_CFG
        print(f"{C_ERROR}[ERROR] Specified brain checkpoint missing at: {os.path.abspath(checkpoint_path)}{C_RESET}")
        print(f"  └── {C_WARN}[SUGGESTION] By default, the verify tool targets the online training brain checkpoint.")
        print(f"      To audit a specific model (e.g. offline trained weights), please specify it explicitly via the -m flag.")
        
        # Scan and list available checkpoints with modified times
        checkpoint_dir = os.path.join(PROJECT_ROOT, RAW_CFG["infrastructure"].get("checkpoint_dir", "checkpoints"))
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
                print(f"      ./run_experiments.sh python --verify-brain -m checkpoints/{pth_files_with_time[0][0]}")
            else:
                print(f"\n      {C_INFO}(No other .pth checkpoint files found in '{checkpoint_dir}' directory){C_RESET}")
        sys.exit(1)

    print(f"[\033[1;34m*\033[0m] Piercing neural tissue... Auditing brain asset: \033[1;32m{os.path.basename(checkpoint_path)}\033[0m\n")
    
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
            
        from src.models.dqn_net import DQNNet
        model = DQNNet(state_dim=input_dim, action_dim=action_dim, hidden_dim=hidden_dim)
        model.load_state_dict(checkpoint)
        model.eval()
        
        translator = DqnActionTranslator()
        print(f"  ├── {C_INFO}Asset Status{C_RESET}  : DQN model loaded successfully.")

    elif is_ppo:
        try:
            input_dim = checkpoint['shared_layer.0.weight'].shape[1]
            hidden_dim = checkpoint['shared_layer.0.weight'].shape[0]
            action_dim = checkpoint['actor_head.0.weight'].shape[0]
            has_two_shared_layers = 'shared_layer.2.weight' in checkpoint
            print(f"  ├── {C_INFO}Detected PPO Model{C_RESET}     : Inputs={input_dim} | Actions={action_dim} | Double Shared Layer={has_two_shared_layers}")
        except KeyError as key_err:
            print(f"{C_ERROR}[FATAL] PPO Checkpoint missing standard key: {key_err}{C_RESET}")
            sys.exit(1)

        from src.models.policy_net import DefencePolicyNet
        model = DefencePolicyNet()
        model.load_state_dict(checkpoint)
        model.eval()

        translator = PpoActionTranslator()
        print(f"  ├── {C_INFO}Asset Status{C_RESET}  : PPO model loaded successfully.")
    else:
        print(f"{C_ERROR}[FATAL] Unknown network weight architecture layout inside checkpoint!{C_RESET}")
        sys.exit(1)

    print("\n================ Brain Decision Verification ================\n")
    consult_brain(model, translator, is_dqn, "NORMAL TRAFFIC", size=325, sq=120, anomaly=0.0)
    consult_brain(model, translator, is_dqn, "ATTACK STORM  ", size=1400, sq=850, anomaly=0.45)

if __name__ == "__main__":
    main()