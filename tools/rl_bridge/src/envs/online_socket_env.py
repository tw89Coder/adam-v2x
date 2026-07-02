"""
@file online_socket_env.py
@brief Gym-style Environment wrapping the TCP Socket IPC for online interactive training.

This module sets up a TCP socket server to interface with the C++ QoS harness.
It acts as a standard RL environment: stepping corresponds to sending actions to C++
and waiting for the next telemetry response.
"""

import socket
import sys
from typing import Tuple, Dict, Any

import torch
from src.config import (
    C_SUCCESS, C_ERROR, RAW_CFG,
    MAX_PACKET_SIZE, MAX_F2_SQ
)
from src.utils.network_io import NetworkIOHelper
from src.envs.base_env import BaseV2XEnv

class V2XOnlineSocketEnv(BaseV2XEnv):
    """
    Standard Gym-style Environment wrapping TCP co-simulation socket connections.
    """
    def __init__(self, host: str = None, port: int = None):
        cfg = RAW_CFG
        self.host = host or cfg["infrastructure"]["host"]
        self.port = port or cfg["infrastructure"]["port"]
        
        # Read reward weights
        r_cfg = cfg["reward_shaping"]
        self.sensitivity_threshold = r_cfg["anomaly_sensitivity_threshold"]
        self.w_active = r_cfg["active_attack_weights"]
        self.w_nominal = r_cfg["nominal_traffic_weights"]
        
        # Server Socket initialization
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"  └── Socket Active : Listening on {self.host}:{self.port}")
        except Exception as e:
            print(f"[FATAL] Cannot bind pipeline server to port {self.port}: {e}")
            sys.exit(1)
            
        self.client_socket = None
        self.current_metrics = None
        
    def build_state_tensor(self, avg_size: float, avg_sq: float, anomaly_rate: float) -> torch.Tensor:
        """
        Constructs normalized 3-dimensional state Tensor.
        Dimensions: [Average Packet Size, Average F2 Sum Square, Anomaly Density Rate]
        """
        norm_size = avg_size / MAX_PACKET_SIZE
        norm_sq = avg_sq / MAX_F2_SQ
        return torch.tensor([norm_size, norm_sq, anomaly_rate], dtype=torch.float32)

    def compute_surrogate_reward(self, serialized_actions: list, anomaly_rate: float, current_budget: float) -> float:
        """
        Multi-objective MDP formulation balancing computational overhead against FSM safety.
        
        @param serialized_actions List of mapped and scaled actions in wire protocol order.
        """
        pred_recovery = serialized_actions[0]
        pred_penalty = serialized_actions[1]
        pred_sq_thresh = serialized_actions[2]
        pred_base_sampling = serialized_actions[3]
        
        if anomaly_rate > self.sensitivity_threshold:
            # Mitigation Phase: Reward high penalty actions but keep tracking budget depletion risks
            reward = (
                (pred_penalty * self.w_active["penalty_scale"]) + 
                (600.0 - pred_sq_thresh) * self.w_active["sq_thresh_scale"] - 
                (1.0 - current_budget / 100.0) * self.w_active["budget_violation_scale"]
            )
        else:
            # Nominal Phase: Reward low latency profiles by penalizing unnecessary high sampling rates
            reward = (
                (pred_recovery * self.w_nominal["recovery_scale"]) + 
                (pred_sq_thresh - 600.0) * self.w_nominal["sq_overhead_scale"] -
                (pred_base_sampling * self.w_nominal["overhead_penalty_scale"])
            )
        return float(reward)

    def _wait_for_telemetry(self) -> Tuple[torch.Tensor, Dict[str, Any]]:
        """
        Blocks until client connects and sends a telemetry transaction payload.
        """
        while True:
            self.client_socket, _ = self.server_socket.accept()
            try:
                raw_data = self.client_socket.recv(1024).decode('utf-8')
                metrics = NetworkIOHelper.parse_telemetry(raw_data)
                
                if metrics is None:
                    self.client_socket.close()
                    continue
                
                # Feature Remapping Engine
                simulated_size = 1400.0 if metrics["anomaly_rate"] > 0.05 else 325.0
                state_tensor = self.build_state_tensor(simulated_size, metrics["avg_sq"], metrics["anomaly_rate"])
                
                self.current_metrics = metrics
                return state_tensor, metrics
            except Exception as e:
                print(f"[ERROR] Socket telemetry receive crash: {e}")
                if self.client_socket:
                    self.client_socket.close()

    def reset(self) -> torch.Tensor:
        """
        Resets environment and blocks until the first telemetry package is received.
        """
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception:
                pass
            self.client_socket = None
            
        state, _ = self._wait_for_telemetry()
        return state

    def step(self, action: list) -> Tuple[torch.Tensor, float, bool, Dict[str, Any]]:
        """
        Send action down the open socket connection, then blocks until the next telemetry arrives.
        
        @param action Mapped continuous action parameters list in wire protocol order.
        """
        # Send action response and close socket transaction
        response = NetworkIOHelper.serialize_policy(action)
        try:
            self.client_socket.send(response)
        except Exception as e:
            print(f"[ERROR] Failed to send action: {e}")
        finally:
            self.client_socket.close()
            self.client_socket = None
            
        # Wait for the NEXT telemetry input from C++ client
        next_state, next_metrics = self._wait_for_telemetry()
        
        # Compute surrogate reward based on current anomaly rate and budget
        reward = self.compute_surrogate_reward(
            action, 
            next_metrics["anomaly_rate"], 
            next_metrics["avg_budget"]
        )
        
        # In online V2X continuous serving, there is no terminal 'done' state
        done = False
        
        info = {
            "metrics": next_metrics,
            "actions_sent": action
        }
        
        return next_state, reward, done, info

    def close(self):
        """
        Safely releases server socket.
        """
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception:
                pass
        try:
            self.server_socket.close()
        except Exception:
            pass
