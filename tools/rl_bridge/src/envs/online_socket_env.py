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
    def __init__(self, host: str = None, port: int = None, action_translator: Any = None, reward_strategy: Any = None):
        cfg = RAW_CFG
        self.host = host or cfg["infrastructure"]["host"]
        self.port = port or cfg["infrastructure"]["port"]
        
        # Read reward weights
        r_cfg = cfg["reward_shaping"]
        self.sensitivity_threshold = r_cfg["anomaly_sensitivity_threshold"]
        self.w_active = r_cfg["active_attack_weights"]
        self.w_nominal = r_cfg["nominal_traffic_weights"]
        
        # === DEVELOPER CONFIG SECTION ===
        # Active features list used to construct the observation state tensor.
        # Options: "avg_sq", "instant_sampling_rate", "anomaly_rate", "true_anomaly_rate", "avg_budget"
        # Edit this list to dynamically change DQN/PPO observation space without modifying method signatures.
        self.active_features = ["instant_sampling_rate", "avg_sq", "anomaly_rate"]
        # =================================
        
        # Strategy Pattern initialization
        from src.envs.translators import PpoActionTranslator
        from src.envs.rewards import PpoSurrogateReward
        
        self.action_translator = action_translator or PpoActionTranslator()
        self.reward_strategy = reward_strategy or PpoSurrogateReward(
            self.sensitivity_threshold, self.w_active, self.w_nominal
        )
        self.action_space = self.action_translator.get_action_space()
        
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
        
    def build_state_tensor(self, metrics: dict) -> torch.Tensor:
        """
        Constructs normalized observation state Tensor dynamically based on active_features.
        """
        state_values = []
        for feature in self.active_features:
            val = metrics[feature]
            if feature == "avg_sq":
                state_values.append(val / MAX_F2_SQ)
            elif feature == "packet_size":
                state_values.append(val / MAX_PACKET_SIZE)
            else:
                state_values.append(val)  # instant_sampling_rate/anomaly_rate/budget/true_rate are already [0.0, 1.0]
        return torch.tensor(state_values, dtype=torch.float32)

    def _wait_for_telemetry(self) -> Tuple[torch.Tensor, Dict[str, Any]]:
        """
        Blocks until client connects and sends a telemetry transaction payload.
        """
        while True:
            self.client_socket, _ = self.server_socket.accept()
            try:
                # Receive exactly 40 bytes binary structure payload
                raw_bytes = self.client_socket.recv(40)
                metrics = NetworkIOHelper.parse_telemetry(raw_bytes)
                
                if metrics is None:
                    self.client_socket.close()
                    continue
                
                # Dynamic state construction based on parsed metrics dictionary
                state_tensor = self.build_state_tensor(metrics)
                
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

    def step(self, action: Any) -> Tuple[torch.Tensor, float, bool, Dict[str, Any]]:
        """
        Send action down the open socket connection, then blocks until the next telemetry arrives.
        """
        # Retrieve the current sampling rate to calculate relative DQN changes
        current_rate = self.current_metrics.get("instant_sampling_rate", 0.10) if self.current_metrics else 0.10
        
        # Translate the action to C++ FSM 4D policy parameters using the strategy
        action_policy = self.action_translator.translate(action, current_rate)
        
        # Send action response and close socket transaction
        response = NetworkIOHelper.serialize_policy(action_policy)
        try:
            self.client_socket.send(response)
        except Exception as e:
            print(f"[ERROR] Failed to send action: {e}")
        finally:
            self.client_socket.close()
            self.client_socket = None
            
        # Wait for the NEXT telemetry input from C++ client
        next_state, next_metrics = self._wait_for_telemetry()
        
        # Compute surrogate reward using the unified metrics payload and the reward strategy
        reward = self.reward_strategy.compute(next_metrics, action_policy)
        
        # In online V2X continuous serving, there is no terminal 'done' state
        done = False
        
        info = {
            "metrics": next_metrics,
            "actions_sent": action_policy
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
