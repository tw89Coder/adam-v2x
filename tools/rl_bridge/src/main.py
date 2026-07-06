"""
@file main.py
@brief Unified system entry point orchestrating online TCP co-simulation or offline dataset training.

This module initializes the neural network model, agent, and environment. It runs the
continuous interaction loop and triggers learning optimization updates when batch sizes are met.
"""

import os
import argparse
from typing import Dict, Any, List
import torch
import pandas as pd

# CRITICAL: Structural auto-path repair to prevent local module discovery failures
import sys
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from src.config import (

    C_INFO, C_SUCCESS, C_WARN, C_ERROR, C_RESET, C_BOLD, C_WHITE,
    HOST, PORT, CHECKPOINT_DIR, ONLINE_BRAIN_PATH, OFFLINE_BRAIN_PATH,
    RAW_CFG, FRAME_STACK
)
from src.utils.data_loader import load_telemetry_data
from src.models.policy_net import DefencePolicyNet
from src.agents.v2x_agent import V2XAgent
from src.envs.online_socket_env import V2XOnlineSocketEnv
from src.envs.offline_dataset_env import V2XOfflineDatasetEnv
from src.algorithms.ppo_learner import PPOLearner
from src.algorithms.sac_learner import SACLearner

def run_online(env: V2XOnlineSocketEnv, agent: V2XAgent, learner: PPOLearner, batch_size: int):
    """
    Continuous online training co-simulation loop interacting with the C++ TCP socket.
    """
    print(f"\n{C_WARN}[*] Refactored Online DRL Serving Active. Waiting for co-simulation connections...{C_RESET}\n")
    
    update_count = 0
    state = env.reset()
    
    # trajectory buffer for rolling online batches
    buffer = {
        "states": [], "actions": [], "log_probs": [],
        "rewards": [], "values": [], "next_states": [], "dones": []
    }
    
    # Initialize CSV logger for recording convergence metrics
    import csv
    import os
    os.makedirs(CHECKPOINT_DIR, exist_ok=True)
    log_path = os.path.join(CHECKPOINT_DIR, "training_progress.csv")
    log_file = open(log_path, mode="w", newline="", encoding="utf-8")
    log_writer = csv.writer(log_file)
    log_writer.writerow(["update", "reward", "loss", "mean_q"])
    
    try:
        while True:
            # 1. Action inference and adaptation
            action, adapted_actions, log_prob, state_value = agent.act(state)
            raw_actions, safe_actions = adapted_actions
            
            # 2. Step environment (send parameters and wait for next observation)
            next_state, reward, done, info = env.step(safe_actions)
            
            # 3. Store transition step in rolling buffer
            buffer["states"].append(state)
            buffer["actions"].append(action)
            buffer["log_probs"].append(log_prob)
            buffer["rewards"].append(torch.tensor([reward], dtype=torch.float32))
            buffer["values"].append(state_value)
            buffer["next_states"].append(next_state)
            buffer["dones"].append(torch.tensor([float(done)], dtype=torch.float32))
            
            state = next_state
            
            # 4. Trigger optimization update when batch size is satisfied
            if len(buffer["states"]) >= batch_size:
                update_count += 1
                
                # Run optimization step on learner
                metrics = learner.update(buffer)
                
                if "q_loss" in metrics:
                    print(
                        f"[{C_INFO}UPDATE #{update_count:03d}{C_RESET}] "
                        f"Mean Reward: {C_SUCCESS if reward >= 0 else C_ERROR}{reward:+6.2f}{C_RESET} | "
                        f"Q Loss: {C_BOLD}{metrics['q_loss']:+.5f}{C_RESET} | "
                        f"Mean Q: {C_BOLD}{metrics['mean_q']:+.5f}{C_RESET} | "
                        f"Target Q: {C_BOLD}{metrics.get('mean_target_q', 0.0):+.5f}{C_RESET} | "
                        f"Replay: {int(metrics.get('replay_size', 0))}"
                    )
                    log_writer.writerow([update_count, reward, metrics['q_loss'], metrics['mean_q']])
                else:
                    print(
                        f"[{C_INFO}UPDATE #{update_count:03d}{C_RESET}] "
                        f"Mean Reward: {C_SUCCESS if reward >= 0 else C_ERROR}{reward:+6.2f}{C_RESET} | "
                        f"Actor Loss: {C_BOLD}{metrics.get('actor_loss', 0.0):+.5f}{C_RESET} | "
                        f"Critic Loss: {C_BOLD}{metrics.get('critic_loss', 0.0):.4f}{C_RESET}"
                    )
                    log_writer.writerow([update_count, reward, metrics.get('actor_loss', 0.0), metrics.get('critic_loss', 0.0)])
                
                log_file.flush()
                
                # Flush rolling buffers
                for key in buffer:
                    buffer[key].clear()
                    
                # print(f"[{C_INFO}UPDATE #{update_count:03d}{C_RESET}] "
                #       f"Mean Reward: {C_SUCCESS}{reward:+6.2f}{C_RESET} | "
                #       f"Actor Loss: {C_BOLD}{metrics['actor_loss']:+.5f}{C_RESET} | "
                #       f"Critic Loss: {C_BOLD}{metrics['critic_loss']:.4f}{C_RESET}")
                
                # Serialize checkpoints periodically
                if update_count % 10 == 0:
                    os.makedirs(CHECKPOINT_DIR, exist_ok=True)
                    torch.save(agent.model.state_dict(), ONLINE_BRAIN_PATH)
                    print(f"  └── {C_SUCCESS}[SUCCESS] Brain weights checkpoint saved -> {ONLINE_BRAIN_PATH}{C_RESET}")
                    
    except KeyboardInterrupt:
        print(f"\n{C_WARN}[*] Interrupted by user. Saving final weights checkpoint to: {ONLINE_BRAIN_PATH}{C_RESET}")
        try:
            os.makedirs(CHECKPOINT_DIR, exist_ok=True)
            torch.save(agent.model.state_dict(), ONLINE_BRAIN_PATH)
            print(f"  └── {C_SUCCESS}[SUCCESS] Final weights successfully saved!{C_RESET}")
        except Exception as save_err:
            print(f"  └── {C_ERROR}[ERROR] Failed to save final weights: {save_err}{C_RESET}")
        print(f"{C_WARN}[*] Releasing TCP server and closing connections safely...{C_RESET}")
    finally:
        log_file.close()
        env.close()

def run_offline(env: V2XOfflineDatasetEnv, agent: V2XAgent, learner: PPOLearner, epochs: int):
    """
    Offline training loop sweeping historical CSV trace datasets.
    """
    print(f"\n{C_INFO}[*] Refactored Offline Training Loop Active. Running {epochs} epochs...{C_RESET}\n")
    
    for epoch in range(epochs):
        epoch_reward = 0.0
        steps = 0
        state = env.reset()
        
        # Buffer containing the entire dataset sweep for on-policy batch updates
        buffer = {
            "states": [], "actions": [], "log_probs": [],
            "rewards": [], "values": [], "next_states": [], "dones": []
        }
        
        done = False
        while not done:
            action, adapted_actions, log_prob, state_value = agent.act(state)
            raw_actions, safe_actions = adapted_actions
            next_state, reward, done, info = env.step(safe_actions)
            
            buffer["states"].append(state)
            buffer["actions"].append(action)
            buffer["log_probs"].append(log_prob)
            buffer["rewards"].append(torch.tensor([reward], dtype=torch.float32))
            buffer["values"].append(state_value)
            buffer["next_states"].append(next_state)
            buffer["dones"].append(torch.tensor([float(done)], dtype=torch.float32))
            
            state = next_state
            epoch_reward += reward
            steps += 1
            
            # Print periodic progress indicator (overwriting the same terminal line)
            if steps % 5000 == 0:
                percent = (steps / env.num_windows) * 100
                print(f"\r  ├── Ingestion progress: {percent:5.1f}% [ {steps}/{env.num_windows} windows ]", end="", flush=True)
            
        # Clear progress line from terminal before displaying the final epoch metrics
        print("\r\033[K", end="", flush=True)
        
        # Update policy weights at the end of the epoch dataset sweep
        metrics = learner.update(buffer)
        
        # Save offline weights after training completes or each epoch
        os.makedirs(CHECKPOINT_DIR, exist_ok=True)
        torch.save(agent.model.state_dict(), OFFLINE_BRAIN_PATH)
        
        if "q_loss" in metrics:
            print(f"  {C_WHITE}──{C_RESET} [ {C_INFO}Epoch {epoch+1:02d}/{epochs:02d}{C_RESET} ] "
                  f"Q Loss: {C_BOLD}{metrics['q_loss']:+.5f}{C_RESET} | "
                  f"Mean Q: {C_BOLD}{metrics.get('mean_q', 0.0):+.5f}{C_RESET} | "
                  f"Mean Reward: {C_SUCCESS}{epoch_reward / steps:+.2f}{C_RESET}")
        else:
            print(f"  {C_WHITE}──{C_RESET} [ {C_INFO}Epoch {epoch+1:02d}/{epochs:02d}{C_RESET} ] "
                  f"Actor Loss: {C_BOLD}{metrics.get('actor_loss', 0.0):+.5f}{C_RESET} | "
                  f"Critic Loss: {C_BOLD}{metrics.get('critic_loss', 0.0):.5f}{C_RESET} | "
                  f"Mean Reward: {C_SUCCESS}{epoch_reward / steps:+.2f}{C_RESET}")

def main():
    parser = argparse.ArgumentParser(description="Unified refactored V2X QoS DRL framework.")
    parser.add_argument("--mode", type=str, choices=["online", "offline"], default="online", help="Execution mode")
    parser.add_argument("--host", type=str, default=None, help="TCP server host")
    parser.add_argument("--port", type=int, default=None, help="TCP server port")
    parser.add_argument("--epochs", type=int, default=10, help="Offline training epochs count")
    parser.add_argument("--rate", type=str, default="mix", help="Offline rate CSV filter ('mix' or float string)")
    parser.add_argument("--frame-stack", type=int, default=None, help="Overrides frame stacking size (k=1 is stateless)")
    parser.add_argument("--fresh", action="store_true", help="Start training from scratch, ignoring existing checkpoints")
    args = parser.parse_args()

    # 1. Dynamic algorithm pipeline building via registry factory
    from src.utils.registry import get_algorithm_builder
    
    # Load offline DataFrame telemetry if offline mode is chosen
    raw_data = load_telemetry_data(args.rate) if args.mode == "offline" else None
    
    algo_name = RAW_CFG.get("algorithm", "ppo").lower()
    lr = RAW_CFG["hyperparameters"]["lr_online"] if args.mode == "online" else RAW_CFG["hyperparameters"]["lr_offline"]
    
    frame_stack = args.frame_stack if args.frame_stack is not None else FRAME_STACK
    
    builder = get_algorithm_builder(algo_name)
    env, agent, learner = builder(
        lr=lr,
        port=args.port,
        mode=args.mode,
        raw_data=raw_data,
        frame_stack=frame_stack
    )
    model = agent.model

    # 2. Instantiate and run environment wrappers dynamically
    if args.mode == "online":
        # Load weights if available
        if not args.fresh and os.path.exists(ONLINE_BRAIN_PATH):
            try:
                model.load_state_dict(torch.load(ONLINE_BRAIN_PATH, map_location="cpu"))
                print(f"  └── {C_SUCCESS}[INIT] Loaded existing online model weights from {ONLINE_BRAIN_PATH}{C_RESET}")
            except Exception as e:
                print(f"  └── {C_WARN}[INIT] Cannot load online model weights: {e}. Starting fresh...{C_RESET}")
        else:
            print(f"  └── {C_INFO}[INIT] Starting training fresh from scratch...{C_RESET}")
                
        # Override env host if provided in CLI arguments
        if args.host:
            env.host = args.host
            
        batch_size = RAW_CFG["hyperparameters"]["batch_size"]
        run_online(env, agent, learner, batch_size)
    else:
        # Load weights if available
        if not args.fresh and os.path.exists(OFFLINE_BRAIN_PATH):
            try:
                model.load_state_dict(torch.load(OFFLINE_BRAIN_PATH, map_location="cpu"))
                print(f"  └── {C_SUCCESS}[INIT] Loaded existing offline model weights from {OFFLINE_BRAIN_PATH}{C_RESET}")
            except Exception as e:
                print(f"  └── {C_WARN}[INIT] Cannot load offline model weights: {e}. Starting fresh...{C_RESET}")
        else:
            print(f"  └── {C_INFO}[INIT] Starting training fresh from scratch...{C_RESET}")
                
        run_offline(env, agent, learner, args.epochs)

if __name__ == "__main__":
    main()
