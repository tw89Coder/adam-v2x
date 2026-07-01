#!/usr/bin/env python3
# ==============================================================================
# V2X QoS DRL Live Production Serve Daemon (Inference Only)
# ==============================================================================
"""
@file serve_agent.py
@brief Live production inference daemon hosting trained DRL models.

This script starts a TCP server on port 8080. It loads optimized brain weights,
locks the model into deterministic evaluation mode (deactivating exploration noise),
and maps incoming telemetry observations directly to policy action means.

NOTE FOR CODE REVIEW:
Line 88 of this script invokes `NetworkIOHelper.serialize_policy` with only 3 
parameters, whereas the helper has been upgraded to take 4 parameters. This causes
a TypeError when incoming connection requests are processed.
"""

import os
import sys

# CRITICAL: Dynamic path adjustment must precede any local 'src' packet imports
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

import socket
import torch

from src.config import MAX_F2_SQ, C_INFO, C_SUCCESS, C_WARN, C_ERROR, C_RESET, RAW_CFG
from src.models.policy_net import DefencePolicyNet
from src.agents.v2x_agent import V2XAgent
from src.utils.network_io import NetworkIOHelper

def main():
    host = "127.0.0.1"
    port = 8080
    
    # Target the optimized brain binary generated from live interactive sessions
    checkpoint_path = "checkpoints/v2x_online_brain.pth" 

    print(f"{C_INFO}┌──────────────────────────────────────────────────────────────┐{C_RESET}")
    print(f"{C_INFO}│       V2X DRL LIVE PRODUCTION INFERENCE SERVE DAEMON         │{C_RESET}")
    print(f"{C_INFO}└──────────────────────────────────────────────────────────────┘{C_RESET}")

    if not os.path.exists(checkpoint_path):
        print(f"{C_ERROR}[FATAL] Target brain asset missing at: {checkpoint_path}{C_RESET}")
        sys.exit(1)

    # Construct network topology and map structural parameters
    model = DefencePolicyNet()
    try:
        model.load_state_dict(torch.load(checkpoint_path))
    except Exception as load_err:
        print(f"{C_ERROR}[FATAL] Failed to load checkpoint binary weights: {load_err}{C_RESET}")
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
                
                # Feature engineering alignment via single source of truth agent helper
                simulated_size = 1400.0 if metrics["anomaly_rate"] > 0.05 else 325.0
                state_tensor = agent.build_state_tensor(simulated_size, metrics["avg_sq"], metrics["anomaly_rate"])
                
                # Execute deterministic inference without exploration variance
                with torch.no_grad():
                    action_mean, _ = model(state_tensor)
                
                # Parse and rescale continuous parameters to C++ functional bounds
                pred_recovery = action_mean[0].item() * 0.5
                pred_penalty  = action_mean[1].item() * 100.0
                pred_sq_thresh = int(400 + (action_mean[2].item() * 400))
                pred_base_samp = 0.05

                # Enforce Heuristic Safety Boundaries to prevent RL from going crazy
                safety_cfg = RAW_CFG.get("safety_boundaries", {})
                if safety_cfg.get("enabled", True):
                    max_sq = safety_cfg.get("max_sq_threshold", 650)
                    min_pen = safety_cfg.get("min_penalty_multiplier", 20.0)
                    max_rec = safety_cfg.get("max_recovery_rate", 0.10)
                    min_samp = safety_cfg.get("min_base_sampling_rate", 0.05)

                    if pred_sq_thresh > max_sq:
                        pred_sq_thresh = max_sq
                    if pred_penalty < min_pen:
                        pred_penalty = min_pen
                    if pred_recovery > max_rec:
                        pred_recovery = max_rec
                    if pred_base_samp < min_samp:
                        pred_base_samp = min_samp

                # Serialize payload and respond to C++ FSM gate
                response = NetworkIOHelper.serialize_policy(pred_recovery, pred_penalty, pred_sq_thresh, pred_base_samp)
                client_socket.send(response)
                
                # Broadcast live production telemetry logging lines
                print(f"[{C_SUCCESS}SERVE{C_RESET}] In -> Anomaly: {metrics['anomaly_rate']*100:4.1f}% | SQ: {metrics['avg_sq']:5.1f} "
                      f"==> Out -> Rec: {pred_recovery:.3f} | Pen: {pred_penalty:4.1f} | SQ_Thresh: {pred_sq_thresh}")
                
            except Exception as e:
                pass
            finally:
                client_socket.close()
    except KeyboardInterrupt:
        print(f"\n{C_WARN}[*] Terminating Production Serve Daemon. Releasing resources...{C_RESET}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()