#!/usr/bin/env python3
# ==============================================================================
# V2X QoS DRL Brain Decision Verification Audit CLI
# ==============================================================================
"""
@file verify_brain.py
@brief Diagnostic evaluation utility auditing offline policy parameters.

This script parses a path to a target brain checkpoint `.pth` file, constructs 
predefined environmental scenarios (Normal traffic baseline and High-potency 
Attack storm), executes forward inference passes through the policy network, 
and prints rescaled output continuous parameter values.
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

def parse_arguments():
    """
    Sets up options for specific brain checkpoints.
    """
    parser = argparse.ArgumentParser(description="Brain Decision Verification Audit CLI")
    parser.add_argument(
        "-m", "--model", 
        type=str, 
        default="checkpoints/v2x_online_brain.pth",
        help="Path to specific target brain checkpoint asset"
    )
    return parser.parse_args()

def consult_brain(model, name, size, sq, anomaly):
    """
    Queries policy network to print model responses to predefined test cases.
    """
    # Construct feature tensor representing the environmental state context
    state = torch.tensor([size/MAX_PACKET_SIZE, sq/MAX_F2_SQ, anomaly], dtype=torch.float32)
    
    with torch.no_grad():
        # Execute forward inference pass to unpack parameters
        action_mean, _ = model(state)
    
    # Scale network outputs back to original C++ operational boundaries
    rec = action_mean[0].item() * 0.5
    pen = action_mean[1].item() * 100.0
    sq_t = 400 + (action_mean[2].item() * 400)
    
    print(f"[{name}] Input: Size={size}B, F2_SQ={sq}, Anomaly={anomaly*100:.1f}%")
    print(f"       -> AI Action: Recovery={rec:.3f}, Penalty={pen:.1f}, SQ_Thresh={int(sq_t)}\n")

def main():
    args = parse_arguments()

    if not os.path.exists(args.model):
        print(f"{C_ERROR}[ERROR] Specified brain checkpoint missing at: {args.model}{C_RESET}")
        print("Please provide a valid path via '-m checkpoints/YOUR_MODEL.pth'")
        sys.exit(1)

    print(f"[\033[1;34m*\033[0m] Piercing neural tissue... Auditing brain asset: \033[1;32m{args.model}\033[0m\n")
    
    # Instantiate neural layers and inject stored binary weights
    model = DefencePolicyNet()
    model.load_state_dict(torch.load(args.model))
    model.eval()

    print("================ Brain Decision Verification ================\n")
    consult_brain(model, "NORMAL TRAFFIC", size=325, sq=120, anomaly=0.0)
    consult_brain(model, "ATTACK STORM  ", size=1400, sq=850, anomaly=0.45)

if __name__ == "__main__":
    main()