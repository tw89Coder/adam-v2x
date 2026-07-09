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

from src.config import C_INFO, C_RESET, C_WARN
from src.models.policy_net import DefencePolicyNet
from src.models.dqn_net import DQNNet
from src.agents.v2x_agent import V2XAgent
from src.agents.dqn_agent import DQNAgent
from src.envs.online_socket_env import V2XOnlineSocketEnv
from src.envs.translators import DqnActionTranslator
from src.envs.rewards import DqnSamplingReward
from src.algorithms.ppo_learner import PPOLearner
from src.algorithms.sac_learner import SACLearner
from src.algorithms.dqn_learner import DQNLearner
from src.main import run_online

def parse_arguments():
    """
    Sets up options for local loopback TCP port allocation and rollout batch limits.
    """
    parser = argparse.ArgumentParser(description="Industrial Online PPO/DQN Coprocessing Console")
    parser.add_argument("-p", "--port", type=int, default=8080, help="Loopback server port assignment")
    parser.add_argument("-b", "--batch", type=int, default=32, help="Rollout batch optimization threshold")
    parser.add_argument("-l", "--lr", type=float, default=0.0003, help="Actor-Critic / Q-Network learning speed")
    parser.add_argument("-a", "--algo", type=str, choices=["ppo", "sac", "dqn"], default="dqn", help="RL algorithm to use")
    parser.add_argument("--frame-stack", type=int, default=None, help="Overrides frame stacking size (k=1 is stateless)")
    return parser.parse_args()

def main():
    args = parse_arguments()

    print(f"{C_INFO}┌──────────────────────────────────────────────────────────────┐{C_RESET}")
    print(f"{C_INFO}│         V2X LIVE ONLINE INTERACTIVE TRAINING SERVER          │{C_RESET}")
    print(f"{C_INFO}└──────────────────────────────────────────────────────────────┘{C_RESET}")
    print(f"  ├── Co-Sim Paradigm : Real-Time Closed-Loop Socket Optimization")
    print(f"  ├── Hyperparameters : Learning Rate -> [ {args.lr} ] | Batch Size -> [ {args.batch} ] | Algo -> [ {args.algo.upper()} ]")

    # Dynamically build the co-simulation training pipeline via registry factory
    from src.utils.registry import get_algorithm_builder
    from src.config import FRAME_STACK
    
    frame_stack = args.frame_stack if args.frame_stack is not None else FRAME_STACK
    
    builder = get_algorithm_builder(args.algo)
    env, agent, learner = builder(
        lr=args.lr,
        port=args.port,
        mode="online",
        frame_stack=frame_stack
    )
        
    # Run the online serving co-simulation loop
    run_online(env, agent, learner, batch_size=args.batch)

if __name__ == "__main__":
    main()