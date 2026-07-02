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

from src.config import C_ERROR, C_RESET, MAX_PACKET_SIZE, MAX_F2_SQ
from src.models.policy_net import DefencePolicyNet 
from src.agents.v2x_agent import V2XAgent

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
    return parser.parse_args()

def consult_brain(agent: V2XAgent, name: str, size: float, sq: float, anomaly: float):
    """
    Queries policy network to print model responses to predefined test cases.
    """
    # Construct feature tensor representing the environmental state context
    state = torch.tensor([size/MAX_PACKET_SIZE, sq/MAX_F2_SQ, anomaly], dtype=torch.float32)
    
    with torch.no_grad():
        # Execute forward inference pass
        action_mean, _ = agent.model(state)
    
    # Map and scale action using Action Adapter
    raw_actions, safe_actions = agent.map_actions_to_environment(action_mean)
    
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
        from src.config import C_WARN, C_INFO, RAW_CFG
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

    print(f"[\033[1;34m*\033[0m] Piercing neural tissue... Auditing brain asset: \033[1;32m{args.model}\033[0m\n")
    
    # Instantiate neural layers and inject stored binary weights
    model = DefencePolicyNet()
    try:
        model.load_state_dict(torch.load(checkpoint_path, map_location="cpu"))
    except Exception as load_err:
        from src.config import C_INFO, C_WARN
        print(f"{C_ERROR}[FATAL] Failed to load checkpoint binary weights!{C_RESET}")
        print(f"  ├── {C_INFO}Target File Path{C_RESET} : {os.path.abspath(checkpoint_path)}")
        print(f"  ├── {C_INFO}Error Message{C_RESET}    : {load_err}")
        print(f"  └── {C_WARN}[SUGGESTION] This size/key mismatch usually occurs when your config/ppo_agent.yaml structure")
        print(f"      (e.g., hidden_layers or active action space dimensions) does not match the loaded checkpoint.")
        print(f"      Please point to a compatible checkpoint or train a new model first.{C_RESET}")
        sys.exit(1)
        
    model.eval()
    agent = V2XAgent(model)

    print("================ Brain Decision Verification ================\n")
    consult_brain(agent, "NORMAL TRAFFIC", size=325, sq=120, anomaly=0.0)
    consult_brain(agent, "ATTACK STORM  ", size=1400, sq=850, anomaly=0.45)

if __name__ == "__main__":
    main()