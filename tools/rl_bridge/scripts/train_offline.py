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
from src.models.dqn_net import DQNNet
from src.agents.v2x_agent import V2XAgent
from src.agents.dqn_agent import DQNAgent
from src.envs.offline_dataset_env import V2XOfflineDatasetEnv
from src.algorithms.ppo_learner import PPOLearner
from src.algorithms.sac_learner import SACLearner
from src.algorithms.dqn_learner import DQNLearner
from src.utils.data_loader import load_telemetry_data
from src.main import run_offline

def parse_arguments():
    """
    Sets up options for sweeps, clipping boundaries, and optimization iterations.
    """
    parser = argparse.ArgumentParser(description="Industrial PRL On-Policy PPO/DQN Optimization Pipeline")
    parser.add_argument("-r", "--rate", type=str, default="mix", help="Target trace training dataset directory filter")
    parser.add_argument("-e", "--epochs", type=int, default=20, help="Total offline matrix sweep iterations")
    parser.add_argument("-l", "--lr", type=float, default=0.001, help="Actor-Critic / Q-Network learning parameter ceiling")
    parser.add_argument("--clip", type=float, default=0.2, help="PPO boundary clipping limits")
    parser.add_argument("-a", "--algo", type=str, choices=["ppo", "sac", "dqn"], default="ppo", help="RL algorithm to use")
    return parser.parse_args()

def main():
    args = parse_arguments()

    print(f"{C_INFO}┌──────────────────────────────────────────────────────────────┐{C_RESET}")
    print(f"{C_INFO}│          DRL POLICY OPTIMIZATION ENGINE SANDBOX              │{C_RESET}")
    print(f"{C_INFO}└──────────────────────────────────────────────────────────────┘{C_RESET}")
    print(f"  ├── Hardware Context : Pytorch Device -> [ {C_BOLD}CPU{C_RESET} ]")
    print(f"  ├── Target Profile   : Anomaly Density -> [ {C_WARN}{args.rate}{C_RESET} ]")
    print(f"  ├── Hyperparameters  : Learning Rate  -> [ {args.lr} ] | PPO Clip -> [ {args.clip} ] | Algo -> [ {args.algo.upper()} ]")

    # Load static CSV simulation historical trajectory dumps
    raw_data = load_telemetry_data(args.rate)

    # Initialize modular standardized components based on algorithm
    if args.algo == "ppo":
        model = DefencePolicyNet()
        agent = V2XAgent(model)
        env = V2XOfflineDatasetEnv(raw_data)
        learner = PPOLearner(agent, lr=args.lr)
    elif args.algo == "dqn":
        model = DQNNet()
        # Note: DqnActionTranslator is not strictly needed for static offline traces,
        # but DQNAgent maps raw actions correctly.
        from src.envs.translators import DqnActionTranslator
        translator = DqnActionTranslator()
        agent = DQNAgent(model, action_translator=translator)
        env = V2XOfflineDatasetEnv(raw_data)
        learner = DQNLearner(agent, lr=args.lr)
    elif args.algo == "sac":
        model = DefencePolicyNet()
        agent = V2XAgent(model)
        env = V2XOfflineDatasetEnv(raw_data)
        learner = SACLearner(agent, lr=args.lr)
        print(f"  └── {C_WARN}[WARNING] Running SAC skeleton template. Neural model weights won't optimize.{C_RESET}")
    else:
        raise ValueError(f"Unsupported algorithm type: {args.algo}")

    print(f"\n{C_WARN}[*] Compiling policy graphs. Executing optimization loops...{C_RESET}\n")
    
    # Launch matrix optimization execution loop
    run_offline(env, agent, learner, args.epochs)

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