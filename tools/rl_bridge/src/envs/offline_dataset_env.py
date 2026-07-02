"""
@file offline_dataset_env.py
@brief Gym-style Environment wrapping pandas CSV historical telemetry frames for offline simulation.

This module exposes a standard step/reset interface that slides over chronologically
recorded traffic sequences, simulating state transitions and evaluating rewards.
"""

from typing import Tuple, Dict, Any
import pandas as pd
import torch

from src.config import WINDOW_SIZE, MAX_PACKET_SIZE, MAX_F2_SQ, RAW_CFG
from src.envs.base_env import BaseV2XEnv

class V2XOfflineDatasetEnv(BaseV2XEnv):
    """
    Offline Environment simulating V2X co-simulation telemetry streams using historical CSV datasets.
    """
    def __init__(self, raw_data: pd.DataFrame):
        self.raw_data = raw_data
        self.total_packets = len(raw_data)
        self.num_windows = self.total_packets // WINDOW_SIZE
        self.current_window = 0
        
        # Read config mapping
        cfg = RAW_CFG
        r_cfg = cfg["reward_shaping"]
        self.sensitivity_threshold = r_cfg["anomaly_sensitivity_threshold"]
        self.w_active = r_cfg["active_attack_weights"]
        self.w_nominal = r_cfg["nominal_traffic_weights"]

    def build_state_tensor(self, avg_size: float, avg_sq: float, anomaly_rate: float) -> torch.Tensor:
        """
        Constructs normalized 3-dimensional state Tensor.
        """
        norm_size = avg_size / MAX_PACKET_SIZE
        norm_sq = avg_sq / MAX_F2_SQ
        return torch.tensor([norm_size, norm_sq, anomaly_rate], dtype=torch.float32)

    def extract_state_from_df(self, df_slice: pd.DataFrame) -> torch.Tensor:
        """
        Parses packet lists from window slices into normalized states.
        """
        avg_size = df_slice["packet_size"].mean()
        avg_sq = df_slice["max_sum_sq"].mean()
        anomaly_rate = df_slice["is_anomalous"].mean()
        return self.build_state_tensor(avg_size, avg_sq, anomaly_rate)

    def compute_surrogate_reward(self, serialized_actions: list, anomaly_rate: float, current_budget: float) -> float:
        """
        Calculates environmental surrogate multi-objective reward matching the online formula.
        """
        pred_recovery = serialized_actions[0]
        pred_penalty = serialized_actions[1]
        pred_sq_thresh = serialized_actions[2]
        pred_base_sampling = serialized_actions[3]
        
        if anomaly_rate > self.sensitivity_threshold:
            reward = (
                (pred_penalty * self.w_active["penalty_scale"]) + 
                (600.0 - pred_sq_thresh) * self.w_active["sq_thresh_scale"] - 
                (1.0 - current_budget / 100.0) * self.w_active["budget_violation_scale"]
            )
        else:
            reward = (
                (pred_recovery * self.w_nominal["recovery_scale"]) + 
                (pred_sq_thresh - 600.0) * self.w_nominal["sq_overhead_scale"] -
                (pred_base_sampling * self.w_nominal["overhead_penalty_scale"])
            )
        return float(reward)

    def reset(self) -> torch.Tensor:
        """
        Resets environment window index to 0.
        """
        self.current_window = 0
        window_slice = self.raw_data.iloc[0 : WINDOW_SIZE]
        return self.extract_state_from_df(window_slice)

    def step(self, action: list) -> Tuple[torch.Tensor, float, bool, Dict[str, Any]]:
        """
        Performs observation sliding window evaluation step.
        """
        # Determine the current window slices
        w = self.current_window
        window_slice = self.raw_data.iloc[w * WINDOW_SIZE : (w + 1) * WINDOW_SIZE]
        next_window_slice = self.raw_data.iloc[(w + 1) * WINDOW_SIZE : (w + 2) * WINDOW_SIZE]
        
        # Calculate next state from next window slice
        next_state = self.extract_state_from_df(next_window_slice)
        
        # Retrieve observations from current slice
        anomaly_rate = window_slice["is_anomalous"].mean()
        current_budget = window_slice["current_budget"].mean()
        
        # Calculate rewards
        reward = self.compute_surrogate_reward(action, anomaly_rate, current_budget)
        
        self.current_window += 1
        done = (self.current_window >= self.num_windows - 1)
        
        info = {
            "window_index": w,
            "actions_sent": action
        }
        
        return next_state, reward, done, info
