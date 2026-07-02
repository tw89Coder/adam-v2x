#!/usr/bin/env python3
# ==============================================================================
# V2X QoS DRL Live Production Serve Daemon (Inference Only)
# ==============================================================================
"""
@file serve_agent.py
@brief Live production inference daemon hosting trained DRL models.

This script starts a TCP server on port 8080. It loads optimized brain weights,
locks the model into deterministic evaluation mode (deactivating exploration noise),
and maps incoming telemetry observations directly to policy action means using the
dynamic Action Adapter.
"""

import os
import sys

# CRITICAL: Dynamic path adjustment must precede any local 'src' imports
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

import socket
import torch
import argparse

from src.config import MAX_PACKET_SIZE, MAX_F2_SQ, C_INFO, C_SUCCESS, C_WARN, C_ERROR, C_RESET, RAW_CFG, ONLINE_BRAIN_PATH
from src.models.policy_net import DefencePolicyNet
from src.agents.v2x_agent import V2XAgent
from src.utils.network_io import NetworkIOHelper

def parse_arguments():
    parser = argparse.ArgumentParser(description="V2X DRL Production Serving Console")
    parser.add_argument("-m", "--model", type=str, default=None, help="Target optimized brain checkpoint path")
    return parser.parse_args()

def main():
    args = parse_arguments()
    host = RAW_CFG["infrastructure"]["host"]
    port = RAW_CFG["infrastructure"]["port"]
    
    # Target the optimized brain binary (command-line override takes priority)
    if args.model:
        checkpoint_path = args.model
        print(f"  ├── {C_INFO}Target Brain{C_RESET} : Loading user-specified checkpoint -> {checkpoint_path}")
    else:
        checkpoint_path = ONLINE_BRAIN_PATH
        print(f"  ├── {C_INFO}Target Brain{C_RESET} : Defaulting to online brain path -> {checkpoint_path}")

    print(f"{C_INFO}┌──────────────────────────────────────────────────────────────┐{C_RESET}")
    print(f"{C_INFO}│       V2X DRL LIVE PRODUCTION INFERENCE SERVE DAEMON         │{C_RESET}")
    print(f"{C_INFO}└──────────────────────────────────────────────────────────────┘{C_RESET}")

    if not os.path.exists(checkpoint_path):
        print(f"{C_ERROR}[FATAL] Target brain asset missing! No checkpoint found at: {os.path.abspath(checkpoint_path)}{C_RESET}")
        print(f"  └── {C_WARN}[SUGGESTION] By default, the serve daemon targets the online training brain checkpoint.")
        print(f"      To load a specific model (e.g. offline trained weights), please specify it explicitly via the -m flag.")
        
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
                print(f"      ./run_experiments.sh python --deploy -m checkpoints/{pth_files_with_time[0][0]}")
            else:
                print(f"\n      {C_INFO}(No other .pth checkpoint files found in '{checkpoint_dir}' directory){C_RESET}")
        sys.exit(1)

    # Construct network topology and map structural parameters
    model = DefencePolicyNet()
    try:
        model.load_state_dict(torch.load(checkpoint_path, map_location="cpu"))
    except Exception as load_err:
        print(f"{C_ERROR}[FATAL] Failed to load checkpoint binary weights!{C_RESET}")
        print(f"  ├── {C_INFO}Target File Path{C_RESET} : {os.path.abspath(checkpoint_path)}")
        print(f"  ├── {C_INFO}Error Message{C_RESET}    : {load_err}")
        print(f"  └── {C_WARN}[SUGGESTION] This size/key mismatch usually occurs when your config/ppo_agent.yaml structure")
        print(f"      (e.g., hidden_layers or active action space dimensions) does not match the loaded checkpoint.")
        print(f"      Please either train a new model to overwrite it, delete the old file, or point to a new checkpoint.")
        sys.exit(1)
        
    # Force evaluation mode to deactivate stochastic exploration noise
    model.eval() 
    agent = V2XAgent(model)
    print(f"  ├── {C_INFO}Asset Status{C_RESET}  : Optimized Brain verified and locked in production mode.")

    # Instantiate loopback IPv4 TCP socket infrastructure
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"  └── {C_SUCCESS}Socket Active{C_RESET} : Production server listening on {host}:{port}")
    except Exception as e:
        print(f"{C_ERROR}[FATAL] Failed to bind socket topology to port {port}: {e}{C_RESET}")
        sys.exit(1)

    print(f"\n{C_WARN}[*] Production pipeline active. Serving optimal deterministic defense actions...{C_RESET}\n")

    try:
        while True:
            client_socket, _ = server_socket.accept()
            try:
                raw_data = client_socket.recv(1024).decode('utf-8')
                metrics = NetworkIOHelper.parse_telemetry(raw_data)
                if metrics is None:
                    client_socket.close()
                    continue
                
                # Feature engineering alignment
                simulated_size = 1400.0 if metrics["anomaly_rate"] > 0.05 else 325.0
                norm_size = simulated_size / MAX_PACKET_SIZE
                norm_sq = metrics["avg_sq"] / MAX_F2_SQ
                state_tensor = torch.tensor([norm_size, norm_sq, metrics["anomaly_rate"]], dtype=torch.float32)
                
                # Execute deterministic inference without exploration variance
                with torch.no_grad():
                    action_mean, _ = model(state_tensor)
                
                # Use the dynamic Action Adapter to scale, map, and enforce safety boundaries
                raw_actions, safe_actions = agent.map_actions_to_environment(action_mean)

                # Serialize payload and respond to C++ FSM gate
                response = NetworkIOHelper.serialize_policy(safe_actions)
                client_socket.send(response)
                
                # Broadcast live production telemetry logging lines
                # Extract recovery, penalty, sq_thresh from the safe_actions layout
                rec_val = safe_actions[0]
                pen_val = safe_actions[1]
                sq_val = safe_actions[2]
                print(f"[{C_SUCCESS}SERVE{C_RESET}] In -> Anomaly: {metrics['anomaly_rate']*100:4.1f}% | SQ: {metrics['avg_sq']:5.1f} "
                      f"==> Out -> Rec: {rec_val:.3f} | Pen: {pen_val:4.1f} | SQ_Thresh: {int(sq_val)}")
                
            except Exception as e:
                print(f"[ERROR] Session transaction fail: {e}")
            finally:
                client_socket.close()
    except KeyboardInterrupt:
        print(f"\n{C_WARN}[*] Terminating Production Serve Daemon. Releasing resources...{C_RESET}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()