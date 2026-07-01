#!/usr/bin/env python3
# ==============================================================================
# V2X QoS Deep Reinforcement Learning Offline PPO Optimization Console Entry
# ==============================================================================
"""
@file train_offline.py
@brief Command-line interface orchestration for batch offline PPO dataset training.

This script parses target anomaly density filters and epoch metrics, imports 
pre-recorded simulation traces from disk using dataset loading components,
and executes historical Proximal Policy Optimization loops to pre-train policy parameters.
"""

import os
import sys
import argparse
import torch

# CRITICAL: Structural auto-path repair to prevent local module discovery failures
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from src.config import C_INFO, C_RESET, C_BOLD, C_WARN, C_SUCCESS, CHECKPOINT_DIR
from src.models.policy_net import DefencePolicyNet
from src.agents.v2x_agent import V2XAgent
from src.pipelines.offline_trainer import V2XOfflinePipeline
from src.utils.data_loader import load_telemetry_data

def parse_arguments():
    """
    Sets up options for sweeps, clipping boundaries, and optimization iterations.
    """
    parser = argparse.ArgumentParser(description="Industrial PRL On-Policy PPO Optimization Pipeline")
    parser.add_argument("-r", "--rate", type=str, default="mix", help="Target trace training dataset directory filter")
    parser.add_argument("-e", "--epochs", type=int, default=20, help="Total offline matrix sweep iterations")
    parser.add_argument("-l", "--lr", type=float, default=0.001, help="Actor-Critic learning parameter ceiling")
    parser.add_argument("--clip", type=float, default=0.2, help="PPO boundary clipping limits")
    return parser.parse_args()

def main():
    args = parse_arguments()

    print(f"{C_INFO}┌──────────────────────────────────────────────────────────────┐{C_RESET}")
    print(f"{C_INFO}│          DRL PPO POLICY OPTIMIZATION ENGINE SANDBOX          │{C_RESET}")
    print(f"{C_INFO}└──────────────────────────────────────────────────────────────┘{C_RESET}")
    print(f"  ├── Hardware Context : Pytorch Device -> [ {C_BOLD}CPU{C_RESET} ]")
    print(f"  ├── Target Profile   : Anomaly Density -> [ {C_WARN}{args.rate}{C_RESET} ]")
    print(f"  ├── Hyperparameters  : Learning Rate  -> [ {args.lr} ] | PPO Clip -> [ {args.clip} ]")

    # Load static CSV simulation historical trajectory dumps
    raw_data = load_telemetry_data(args.rate)

    # Initialize modular standardized components
    model = DefencePolicyNet()
    agent = V2XAgent(model)
    
    # Bind dependencies to pipeline controller 
    pipeline = V2XOfflinePipeline(agent, lr=args.lr, clip_eps=args.clip, ppo_epochs=10)

    print(f"\n{C_WARN}[*] Compiling policy graphs. Executing Proximal Policy Optimization loops...{C_RESET}\n")
    
    # Launch matrix optimization execution loop
    pipeline.train_episodes(raw_data, args.epochs)

    # Export optimized binary parameters
    os.makedirs(CHECKPOINT_DIR, exist_ok=True)
    weight_output_path = f"{CHECKPOINT_DIR}/v2x_offline_r{args.rate}_e{args.epochs}.pth"
    torch.save(model.state_dict(), weight_output_path)
    
    print(f"\n{C_SUCCESS}┌───────────────────────────────────────────────────────────────┐{C_RESET}")
    print(f"{C_SUCCESS}│     PROXIMAL POLICY OPTIMIZATION COMPLETE - BRAIN ALIGNED     │{C_RESET}")
    print(f"{C_SUCCESS}└───────────────────────────────────────────────────────────────┘{C_RESET}")
    print(f"  └── Model Assets Exported Successfully -> [ {C_BOLD}{weight_output_path}{C_RESET} ]\n")

if __name__ == "__main__":
    main()