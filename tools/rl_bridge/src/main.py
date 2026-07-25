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
        "rewards": [], "values": [], "next_states": [], "dones": [],
        "leakage_rates": [],
        "inspection_rates": [],
        "target_sampling_rates": [],
        "attack_intensities": [],
        "fprs": [],
        "fnrs": [],
        "inspected_counts": [],
        "total_packets": [],
        "total_sq": [],
        "total_latency_ticks": [],
        "tp_counts": [],
        "tn_counts": [],
        "fp_counts": [],
        "fn_counts": [],
        "greedy_actions": []
    }
    
    # Initialize CSV logger for recording convergence metrics
    import csv
    import os
    os.makedirs(CHECKPOINT_DIR, exist_ok=True)
    algorithm_name = getattr(agent, "algorithm_name", None)
    log_suffix = f"_{algorithm_name}" if algorithm_name else ""
    checkpoint_path = (
        os.path.join(CHECKPOINT_DIR, f"v2x_online_brain_{algorithm_name}.pth")
        if algorithm_name
        else ONLINE_BRAIN_PATH
    )
    log_path = os.path.join(CHECKPOINT_DIR, f"training_progress{log_suffix}.csv")
    log_file = open(log_path, mode="w", newline="", encoding="utf-8")
    progress_fields = [
        "update", "step", "rollout_steps",
        "reward_mean", "reward_std", "reward_min", "reward_max",
        "actor_loss", "critic_loss", "total_loss", "entropy",
        "approx_kl", "clip_fraction", "explained_variance", "grad_norm",
        "value_mean", "return_mean", "advantage_mean", "advantage_std",
        "learning_rate", "lambda_penalty", "leakage_target",
        "packet_count", "malware_count", "inspected_count",
        "inspection_rate", "target_sampling_rate_mean", "attack_rate",
        "detected_anomaly_rate", "fpr", "fnr", "precision", "recall",
        "avg_sq", "avg_processing_latency_ticks",
        "tp", "tn", "fp", "fn",
        "action_0_count", "action_1_count", "action_2_count", "action_3_count", "action_4_count",
        "action_0_fraction", "action_1_fraction", "action_2_fraction", "action_3_fraction", "action_4_fraction",
        "greedy_action_0_fraction", "greedy_action_1_fraction", "greedy_action_2_fraction",
        "greedy_action_3_fraction", "greedy_action_4_fraction",
    ]
    log_writer = csv.DictWriter(log_file, fieldnames=progress_fields)
    log_writer.writeheader()

    # Initialize CSV logger for step-by-step training telemetry curves
    telemetry_path = os.path.join(CHECKPOINT_DIR, f"online_training_telemetry{log_suffix}.csv")
    telemetry_file = open(telemetry_path, mode="w", newline="", encoding="utf-8")
    telemetry_fields = [
        "step", "update", "rollout_step", "reward",
        "action_index", "action_delta", "sampling_rate_before", "sampling_rate_after",
        "action_log_prob", "chosen_action_probability", "state_value",
        "greedy_action_index", "policy_prob_0", "policy_prob_1", "policy_prob_2", "policy_prob_3", "policy_prob_4",
        "packet_count", "malware_count", "benign_count", "inspected_count",
        "actual_inspection_rate", "attack_rate", "detected_anomaly_rate",
        "leakage_rate", "fpr", "fnr", "precision", "recall",
        "avg_sq", "total_sq", "avg_processing_latency_ticks", "total_latency_ticks",
        "tp", "tn", "fp", "fn",
    ]
    telemetry_writer = csv.DictWriter(telemetry_file, fieldnames=telemetry_fields)
    telemetry_writer.writeheader()

    print(f"  └── {C_SUCCESS}[ACTIVE]{C_RESET} Step-by-step training telemetry logging -> {C_BOLD}{telemetry_path}{C_RESET}")
    step_count = 0
    
    try:
        while True:
            # 1. Action inference and adaptation
            action, adapted_actions, log_prob, state_value = agent.act(state)
            raw_actions, safe_actions = adapted_actions

            policy_probs = []
            greedy_action_index = ""
            if getattr(agent, "algorithm_name", "") == "discrete_ppo":
                with torch.no_grad():
                    eval_dist, _ = agent.get_action_distribution(state)
                    policy_probs = eval_dist.probs.detach().cpu().reshape(-1).tolist()
                    greedy_action_index = int(torch.argmax(eval_dist.probs).item())
            
            # 2. Step environment (send parameters and wait for next observation)
            next_state, reward, done, info = env.step(safe_actions)
            step_count += 1

            # Record step telemetry to CSV file
            if "metrics" in info:
                m = info["metrics"]
                tp, tn = m.get("tp_count", 0), m.get("tn_count", 0)
                fp, fn = m.get("fp_count", 0), m.get("fn_count", 0)
                tot = tp + tn + fp + fn
                safe_tot = max(tot, 1)
                inspected = m.get("inspected_count", 0)
                malware, benign = tp + fn, tn + fp
                action_map = getattr(agent.action_translator, "action_map", None)
                if action_map is not None and action.numel() == 1:
                    action_index = int(action.item())
                    action_delta = action_map[action_index]
                else:
                    action_index = ""
                    action_delta = ""
                sent_policy = info.get("actions_sent", [])
                sampling_after = sent_policy[3] if len(sent_policy) > 3 else float("nan")
                sampling_before = float(state[-3].item()) if state.numel() >= 3 else float("nan")
                telemetry_writer.writerow({
                    "step": step_count,
                    "update": update_count,
                    "rollout_step": len(buffer["states"]) + 1,
                    "reward": reward,
                    "action_index": action_index,
                    "action_delta": action_delta,
                    "sampling_rate_before": sampling_before,
                    "sampling_rate_after": sampling_after,
                    "action_log_prob": float(log_prob.item()),
                    "chosen_action_probability": float(torch.exp(log_prob).item()),
                    "state_value": float(state_value.item()),
                    "greedy_action_index": greedy_action_index,
                    **{
                        f"policy_prob_{index}": policy_probs[index] if index < len(policy_probs) else ""
                        for index in range(5)
                    },
                    "packet_count": tot,
                    "malware_count": malware,
                    "benign_count": benign,
                    "inspected_count": inspected,
                    "actual_inspection_rate": inspected / safe_tot,
                    "attack_rate": malware / safe_tot,
                    "detected_anomaly_rate": (tp + fp) / safe_tot,
                    "leakage_rate": m.get("leakage_rate", 0.0),
                    "fpr": m.get("fpr", 0.0),
                    "fnr": m.get("fnr", 0.0),
                    "precision": m.get("precision", 0.0),
                    "recall": m.get("recall", 0.0),
                    "avg_sq": m.get("avg_sq", 0.0),
                    "total_sq": m.get("total_sq", 0),
                    "avg_processing_latency_ticks": m.get("total_latency_ticks", 0) / safe_tot,
                    "total_latency_ticks": m.get("total_latency_ticks", 0),
                    "tp": tp, "tn": tn, "fp": fp, "fn": fn,
                })
            
            # 3. Store transition step in rolling buffer
            buffer["states"].append(state)
            buffer["actions"].append(action)
            buffer["log_probs"].append(log_prob)
            buffer["rewards"].append(torch.tensor([reward], dtype=torch.float32))
            buffer["values"].append(state_value)
            buffer["next_states"].append(next_state)
            buffer["dones"].append(torch.tensor([float(done)], dtype=torch.float32))
            buffer["greedy_actions"].append(greedy_action_index)
            # Store leakage rate for Lagrangian penalty update
            if "metrics" in info:
                m = info["metrics"]

                tp = m.get("tp_count", 0)
                tn = m.get("tn_count", 0)
                fp = m.get("fp_count", 0)
                fn = m.get("fn_count", 0)

                tot = tp + tn + fp + fn
                if tot == 0:
                    tot = 1

                actual_insp = m.get("inspected_count", 0) / tot

                buffer["leakage_rates"].append(m.get("leakage_rate", 0.0))
                buffer["inspection_rates"].append(actual_insp)
                buffer["target_sampling_rates"].append(m.get("instant_sampling_rate", 0.0))
                buffer["attack_intensities"].append(m.get("true_anomaly_rate", 0.0))
                buffer["fprs"].append(m.get("fpr", 0.0))
                buffer["fnrs"].append(m.get("fnr", 0.0))
                buffer["inspected_counts"].append(m.get("inspected_count", 0))
                buffer["total_packets"].append(tot)
                buffer["total_sq"].append(m.get("total_sq", 0))
                buffer["total_latency_ticks"].append(m.get("total_latency_ticks", 0))
                buffer["tp_counts"].append(tp)
                buffer["tn_counts"].append(tn)
                buffer["fp_counts"].append(fp)
                buffer["fn_counts"].append(fn)

            
            state = next_state
            
            # 4. Trigger optimization update when batch size is satisfied
            if len(buffer["states"]) >= batch_size:
                update_count += 1
                
                # Run optimization step on learner
                metrics = learner.update(buffer)

                def safe_mean(xs):
                    return sum(xs) / len(xs) if len(xs) > 0 else 0.0

                reward_values = [r.item() for r in buffer["rewards"]]
                batch_mean_reward = safe_mean(reward_values)

                avg_inspection_rate = safe_mean(buffer["inspection_rates"])
                avg_target_sampling_rate = safe_mean(buffer["target_sampling_rates"])
                avg_attack_intensity = safe_mean(buffer["attack_intensities"])
                avg_fpr = safe_mean(buffer["fprs"])
                avg_fnr = safe_mean(buffer["fnrs"])

                sum_tp = sum(buffer["tp_counts"])
                sum_tn = sum(buffer["tn_counts"])
                sum_fp = sum(buffer["fp_counts"])
                sum_fn = sum(buffer["fn_counts"])
                sum_packets = sum(buffer["total_packets"])
                sum_inspected = sum(buffer["inspected_counts"])
                sum_sq = sum(buffer["total_sq"])
                sum_latency = sum(buffer["total_latency_ticks"])

                
                
                # Update Lagrangian multiplier for constrained DQN reward
                if hasattr(env.reward_strategy, "update_lambda") and len(buffer["leakage_rates"]) > 0:
                    rollout_malware_count = sum_tp + sum_fn
                    avg_leakage_rate = (
                        sum_fn / rollout_malware_count
                        if rollout_malware_count > 0
                        else 0.0
                    )
                    current_lambda = env.reward_strategy.update_lambda(avg_leakage_rate)

                    metrics["avg_leakage_rate"] = avg_leakage_rate
                    metrics["lambda_penalty"] = current_lambda
                
                
                if "q_loss" in metrics:
                    print(
                        f"[{C_INFO}UPDATE #{update_count:03d}{C_RESET}] "
                        f"Batch Reward: {C_SUCCESS if batch_mean_reward >= 0 else C_ERROR}{batch_mean_reward:+6.2f}{C_RESET} | "
                        f"Q Loss: {C_BOLD}{metrics['q_loss']:+.5f}{C_RESET} | "
                        f"Mean Q: {C_BOLD}{metrics['mean_q']:+.5f}{C_RESET} | "
                        f"Target Q: {C_BOLD}{metrics.get('mean_target_q', 0.0):+.5f}{C_RESET} | "
                        f"Leakage: {C_BOLD}{metrics.get('avg_leakage_rate', 0.0):.4f}{C_RESET} | "
                        f"Lambda: {C_BOLD}{metrics.get('lambda_penalty', 0.0):.3f}{C_RESET} | "
                        f"Replay: {int(metrics.get('replay_size', 0))}"
                    )

                    # The progress schema is PPO-oriented. Keep common QoS
                    # fields usable when this shared loop runs DQN as well.
                    malware_count = sum_tp + sum_fn
                    benign_count = sum_tn + sum_fp
                    detected_count = sum_tp + sum_fp
                    log_writer.writerow({
                        "update": update_count,
                        "step": step_count,
                        "rollout_steps": len(buffer["states"]),
                        "reward_mean": batch_mean_reward,
                        "reward_std": float(torch.tensor(reward_values).std(unbiased=False).item()),
                        "reward_min": min(reward_values),
                        "reward_max": max(reward_values),
                        "total_loss": metrics.get("q_loss", 0.0),
                        "lambda_penalty": metrics.get("lambda_penalty", 0.0),
                        "leakage_target": getattr(env.reward_strategy, "leakage_target", 0.0),
                        "packet_count": sum_packets,
                        "malware_count": malware_count,
                        "inspected_count": sum_inspected,
                        "inspection_rate": sum_inspected / max(sum_packets, 1),
                        "target_sampling_rate_mean": avg_target_sampling_rate,
                        "attack_rate": malware_count / max(sum_packets, 1),
                        "detected_anomaly_rate": detected_count / max(sum_packets, 1),
                        "fpr": sum_fp / max(benign_count, 1),
                        "fnr": sum_fn / max(malware_count, 1),
                        "precision": sum_tp / max(detected_count, 1),
                        "recall": sum_tp / max(malware_count, 1),
                        "avg_sq": sum_sq / max(sum_packets, 1),
                        "avg_processing_latency_ticks": sum_latency / max(sum_packets, 1),
                        "tp": sum_tp, "tn": sum_tn, "fp": sum_fp, "fn": sum_fn,
                    })
                else:
                    print(
                        f"[{C_INFO}UPDATE #{update_count:03d}{C_RESET}] "
                        f"Mean Reward: {C_SUCCESS if reward >= 0 else C_ERROR}{reward:+6.2f}{C_RESET} | "
                        f"Actor Loss: {C_BOLD}{metrics.get('actor_loss', 0.0):+.5f}{C_RESET} | "
                        f"Critic Loss: {C_BOLD}{metrics.get('critic_loss', 0.0):.4f}{C_RESET}"
                    )
                    malware_count = sum_tp + sum_fn
                    benign_count = sum_tn + sum_fp
                    detected_count = sum_tp + sum_fp
                    action_counts = [0] * 5
                    action_map = getattr(agent.action_translator, "action_map", None)
                    if action_map is not None:
                        for buffered_action in buffer["actions"]:
                            index = int(buffered_action.item())
                            if 0 <= index < len(action_counts):
                                action_counts[index] += 1
                    rollout_len = len(buffer["states"])
                    row = {
                        "update": update_count,
                        "step": step_count,
                        "rollout_steps": rollout_len,
                        "reward_mean": batch_mean_reward,
                        "reward_std": float(torch.tensor(reward_values).std(unbiased=False).item()),
                        "reward_min": min(reward_values),
                        "reward_max": max(reward_values),
                        "actor_loss": metrics.get("actor_loss", 0.0),
                        "critic_loss": metrics.get("critic_loss", 0.0),
                        "total_loss": metrics.get("total_loss", 0.0),
                        "entropy": metrics.get("entropy", 0.0),
                        "approx_kl": metrics.get("approx_kl", 0.0),
                        "clip_fraction": metrics.get("clip_fraction", 0.0),
                        "explained_variance": metrics.get("explained_variance", 0.0),
                        "grad_norm": metrics.get("grad_norm", 0.0),
                        "value_mean": metrics.get("value_mean", 0.0),
                        "return_mean": metrics.get("return_mean", 0.0),
                        "advantage_mean": metrics.get("advantage_mean", 0.0),
                        "advantage_std": metrics.get("advantage_std", 0.0),
                        "learning_rate": metrics.get("learning_rate", 0.0),
                        "lambda_penalty": metrics.get("lambda_penalty", 0.0),
                        "leakage_target": getattr(env.reward_strategy, "leakage_target", 0.0),
                        "packet_count": sum_packets,
                        "malware_count": malware_count,
                        "inspected_count": sum_inspected,
                        "inspection_rate": sum_inspected / max(sum_packets, 1),
                        "target_sampling_rate_mean": avg_target_sampling_rate,
                        "attack_rate": malware_count / max(sum_packets, 1),
                        "detected_anomaly_rate": detected_count / max(sum_packets, 1),
                        "fpr": sum_fp / max(benign_count, 1),
                        "fnr": sum_fn / max(malware_count, 1),
                        "precision": sum_tp / max(detected_count, 1),
                        "recall": sum_tp / max(malware_count, 1),
                        "avg_sq": sum_sq / max(sum_packets, 1),
                        "avg_processing_latency_ticks": sum_latency / max(sum_packets, 1),
                        "tp": sum_tp, "tn": sum_tn, "fp": sum_fp, "fn": sum_fn,
                    }
                    if action_map is not None:
                        for index, count in enumerate(action_counts):
                            row[f"action_{index}_count"] = count
                            row[f"action_{index}_fraction"] = count / max(rollout_len, 1)
                        greedy_counts = [0] * len(action_counts)
                        for greedy_index in buffer["greedy_actions"]:
                            if isinstance(greedy_index, int) and 0 <= greedy_index < len(greedy_counts):
                                greedy_counts[greedy_index] += 1
                        for index, count in enumerate(greedy_counts):
                            row[f"greedy_action_{index}_fraction"] = count / max(rollout_len, 1)
                    log_writer.writerow(row)
                
                log_file.flush()
                telemetry_file.flush()
                
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
                    torch.save(agent.model.state_dict(), checkpoint_path)
                    print(f"  └── {C_SUCCESS}[SUCCESS] Brain weights checkpoint saved -> {checkpoint_path}{C_RESET}")
                    
    except KeyboardInterrupt:
        print(f"\n{C_WARN}[*] Interrupted by user. Saving final weights checkpoint to: {checkpoint_path}{C_RESET}")
        try:
            os.makedirs(CHECKPOINT_DIR, exist_ok=True)
            torch.save(agent.model.state_dict(), checkpoint_path)
            print(f"  └── {C_SUCCESS}[SUCCESS] Final weights successfully saved!{C_RESET}")
        except Exception as save_err:
            print(f"  └── {C_ERROR}[ERROR] Failed to save final weights: {save_err}{C_RESET}")
        print(f"{C_WARN}[*] Releasing TCP server and closing connections safely...{C_RESET}")
    finally:
        log_file.close()
        telemetry_file.close()
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
    parser.add_argument("-a", "--algo", "--algorithm", dest="algo", type=str, choices=["ppo", "discrete_ppo", "sac", "dqn"], default=None,
                        help="RL algorithm to use (defaults to config/agent.yaml)")
    args = parser.parse_args()

    # 1. Dynamic algorithm pipeline building via registry factory
    from src.utils.registry import get_algorithm_builder
    
    # Load offline DataFrame telemetry if offline mode is chosen
    raw_data = load_telemetry_data(args.rate) if args.mode == "offline" else None
    
    algo_name = (args.algo or RAW_CFG.get("algorithm", "ppo")).lower()
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
    selected_online_brain_path = (
        os.path.join(CHECKPOINT_DIR, f"v2x_online_brain_{algo_name}.pth")
        if algo_name == "discrete_ppo"
        else ONLINE_BRAIN_PATH
    )

    # 2. Instantiate and run environment wrappers dynamically
    if args.mode == "online":
        # Load weights if available
        if not args.fresh and os.path.exists(selected_online_brain_path):
            try:
                model.load_state_dict(torch.load(selected_online_brain_path, map_location="cpu"))
                print(f"  └── {C_SUCCESS}[INIT] Loaded existing online model weights from {selected_online_brain_path}{C_RESET}")
            except Exception as e:
                print(f"  └── {C_WARN}[INIT] Cannot load online model weights: {e}. Starting fresh...{C_RESET}")
        else:
            print(f"  └── {C_INFO}[INIT] Starting training fresh from scratch...{C_RESET}")
                
        # Override env host if provided in CLI arguments
        if args.host:
            env.host = args.host
            
        batch_size = RAW_CFG.get(algo_name, {}).get(
            "rollout_steps", RAW_CFG["hyperparameters"]["batch_size"]
        )
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
