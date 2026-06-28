#!/usr/bin/env python3
import os
import argparse
import torch
import torch.nn as nn
import torch.optim as optim

from src.config import *
from src.network import DefencePolicyNet
from src.utils.data_loader import load_telemetry_data
from src.agent import V2XAgent

def parse_arguments():
    parser = argparse.ArgumentParser(description="Industrial DRL Offline Optimization Pipeline")
    parser.add_argument("-r", "--rate", type=str, default="1.0", help="Target selector ('mix' or float string)")
    parser.add_argument("-e", "--epochs", type=int, default=10, help="Total optimization iterations")
    parser.add_argument("-l", "--lr", type=float, default=0.005, help="Learning rate parameter")
    return parser.parse_args()

def main():
    args = parse_arguments()

    print(f"{C_INFO}┌──────────────────────────────────────────────────────────────┐{C_RESET}")
    print(f"{C_INFO}│          DRL OFFLINE KNOWLEDGE DISTILLATION SANDBOX          │{C_RESET}")
    print(f"{C_INFO}└──────────────────────────────────────────────────────────────┘{C_RESET}")
    print(f"  ├── Hardware Context : Pytorch Device -> [ {C_BOLD}CPU{C_RESET} ]")
    print(f"  ├── Target Profile   : Anomaly Density -> [ {C_WARN}{args.rate}{C_RESET} ]")
    print(f"  ├── Hyperparameters  : Learning Rate  -> [ {args.lr} ] | Total Epochs -> [ {args.epochs} ]")

    # Ingest data via the Data Loader module
    raw_data = load_telemetry_data(args.rate)

    # Initialize components
    model = DefencePolicyNet()
    agent = V2XAgent(model)
    optimizer = optim.Adam(model.parameters(), lr=args.lr)

    total_packets = len(raw_data)
    num_windows = total_packets // WINDOW_SIZE

    print(f"\n{C_WARN}[*] Compiling optimization graph pipelines. Triggering backpropagation loops...{C_RESET}\n")

    for epoch in range(args.epochs):
        epoch_loss = 0.0
        epoch_reward = 0.0
        
        for w in range(num_windows):
            window_slice = raw_data.iloc[w * WINDOW_SIZE : (w + 1) * WINDOW_SIZE]
            
            # Delegate feature calculation and forward propagation to Agent module
            action, target_action, reward = agent.evaluate_window(window_slice)
            epoch_reward += reward
            
            loss = nn.MSELoss()(action, target_action)
            
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            
            epoch_loss += loss.item()
            
        mean_loss = epoch_loss / num_windows
        print(f"  {C_WHITE}──{C_RESET} [ {C_INFO}Epoch {epoch+1:02d}/{args.epochs:02d}{C_RESET} ] "
              f"Convergence Loss: {C_BOLD}{mean_loss:.6f}{C_RESET} | "
              f"Cumulative Reward Scalar: {C_SUCCESS}{epoch_reward:+.2f}{C_RESET}")

    # Export compiled weights asset
    os.makedirs(CHECKPOINT_DIR, exist_ok=True)
    weight_output_path = f"{CHECKPOINT_DIR}/v2x_offline_r{args.rate}_e{args.epochs}.pth"
    torch.save(model.state_dict(), weight_output_path)
    
    print(f"\n{C_SUCCESS}┌───────────────────────────────────────────────────────────────┐{C_RESET}")
    print(f"{C_SUCCESS}│     OFFLINE POLICY OPTIMIZATION COMPLETE - WEIGHT CONVERGED   │{C_RESET}")
    print(f"{C_SUCCESS}└───────────────────────────────────────────────────────────────┘{C_RESET}")
    print(f"  └── Model Assets Exported Successfully -> [ {C_BOLD}{weight_output_path}{C_RESET} ]\n")

if __name__ == "__main__":
    main()