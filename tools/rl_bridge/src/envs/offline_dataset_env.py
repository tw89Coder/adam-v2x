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
    def __init__(self, raw_data: pd.DataFrame, action_translator: Any = None, reward_strategy: Any = None):
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
        
        # Strategy Pattern initialization
        from src.envs.translators import PpoActionTranslator
        from src.envs.rewards import PpoSurrogateReward
        
        self.action_translator = action_translator or PpoActionTranslator()
        self.reward_strategy = reward_strategy or PpoSurrogateReward(
            self.sensitivity_threshold, self.w_active, self.w_nominal
        )
        self.action_space = self.action_translator.get_action_space()

    def build_state_tensor(self, current_rate: float, avg_sq: float, anomaly_rate: float) -> torch.Tensor:
        """
        Constructs normalized 3-dimensional state Tensor.
        """
        import numpy as np
        # Defensive validation against corrupt or out-of-bound dataset entries
        current_rate = float(np.clip(current_rate, 0.0, 1.0)) if np.isfinite(current_rate) else 0.05
        avg_sq = float(np.clip(avg_sq, 0.0, MAX_F2_SQ)) if np.isfinite(avg_sq) else 0.0
        anomaly_rate = float(np.clip(anomaly_rate, 0.0, 1.0)) if np.isfinite(anomaly_rate) else 0.0

        norm_sq = avg_sq / MAX_F2_SQ
        return torch.tensor([current_rate, norm_sq, anomaly_rate], dtype=torch.float32)

    def extract_state_from_df(self, df_slice: pd.DataFrame) -> torch.Tensor:
        """
        Parses packet lists from window slices into normalized states.
        """
        avg_sq = df_slice["max_sum_sq"].mean()
        anomaly_rate = df_slice["is_anomalous"].mean()
        
        # Extract budget and convert to rate to match online socket env
        current_budget = df_slice["current_budget"].mean()
        import numpy as np
        if not np.isfinite(current_budget) or current_budget < 0.0 or current_budget > 100.0:
            current_budget = float(np.clip(current_budget, 0.0, 100.0))
            if not np.isfinite(current_budget):
                current_budget = 100.0
        current_rate = current_budget / 100.0
        
        return self.build_state_tensor(current_rate, avg_sq, anomaly_rate)

    def reset(self) -> torch.Tensor:
        """
        Resets environment window index to 0.
        """
        self.current_window = 0
        window_slice = self.raw_data.iloc[0 : WINDOW_SIZE]
        return self.extract_state_from_df(window_slice)

    def step(self, action: Any) -> Tuple[torch.Tensor, float, bool, Dict[str, Any]]:
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
        
        # Defensive validation: clamp budget to valid range [0.0, 100.0] and handle underflow garbage values
        import numpy as np
        if not np.isfinite(current_budget) or current_budget < 0.0 or current_budget > 100.0:
            current_budget = float(np.clip(current_budget, 0.0, 100.0))
            if not np.isfinite(current_budget):
                current_budget = 100.0 # Default fallback to full budget
                
        current_rate = current_budget / 100.0  # Scale budget to [0.0, 1.0] for translation
        
        # Translate the action to C++ FSM 4D policy parameters using the strategy
        action_policy = self.action_translator.translate(action, current_rate)
        
        # Compute reward using the reward strategy
        # Prepare metrics dictionary matching online socket structure
        metrics = {
            "anomaly_rate": anomaly_rate,
            "true_anomaly_rate": anomaly_rate,
            "leakage_rate": 0.0,
            "instant_sampling_rate": current_rate,
            "avg_budget": current_rate
        }
        
        # Calculate reward using the strategy
        reward = self.reward_strategy.compute(metrics, action_policy)
        
        self.current_window += 1
        done = (self.current_window >= self.num_windows - 1)
        
        info = {
            "window_index": w,
            "actions_sent": action_policy
        }
        
        return next_state, reward, done, info
