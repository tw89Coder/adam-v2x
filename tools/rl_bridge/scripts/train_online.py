#!/usr/bin/env python3
# ==============================================================================
# V2X QoS Interactive Online Reinforcement Learning Suite CLI
# ==============================================================================
"""
@file train_online.py
@brief Command-line interface orchestration for online interactive socket DRL training.

This script parses arguments, initializes the Policy Net and V2XAgent wrapping layers,
and delegates runtime execution to the socket-listening online training pipeline server.
"""

import os
import sys
import argparse

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from src.config import C_INFO, C_RESET
from src.models.policy_net import DefencePolicyNet
from src.agents.v2x_agent import V2XAgent
from src.pipelines.online_server import V2XOnlinePipeline

def parse_arguments():
    """
    Sets up options for local loopback TCP port allocation and rollout batch limits.
    """
    parser = argparse.ArgumentParser(description="Industrial Online PPO Coprocessing Console")
    parser.add_argument("-p", "--port", type=int, default=8080, help="Loopback server port assignment")
    parser.add_argument("-b", "--batch", type=int, default=32, help="Rollout batch optimization threshold")
    parser.add_argument("-l", "--lr", type=float, default=0.0003, help="Actor-Critic learning speed")
    return parser.parse_args()

def main():
    args = parse_arguments()

    print(f"{C_INFO}┌──────────────────────────────────────────────────────────────┐{C_RESET}")
    print(f"{C_INFO}│         V2X PPO LIVE ONLINE INTERACTIVE TRAINING SERVER      │{C_RESET}")
    print(f"{C_INFO}└──────────────────────────────────────────────────────────────┘{C_RESET}")
    print(f"  ├── Co-Sim Paradigm : Real-Time Closed-Loop Socket Optimization")
    print(f"  ├── Hyperparameters : Learning Rate -> [ {args.lr} ] | Batch Size -> [ {args.batch} ]")

    # Layer initialization via industrial components
    model = DefencePolicyNet()
    agent = V2XAgent(model)
    
    # Inject dependencies into pipeline controller
    pipeline = V2XOnlinePipeline(agent, lr=args.lr, batch_size=args.batch)
    pipeline.start_server(port=args.port)

if __name__ == "__main__":
    main()