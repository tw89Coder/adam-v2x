"""
@file v2x_agent.py
@brief Agent wrapper managing state tensor mapping, Gaussian action distribution parameters, and reward shaping.

This module houses the V2XAgent coordinator. It bridges state observations into 
normalized torch Tensors and implements the multi-objective surrogate reward
objective function.

NOTE FOR CODE REVIEW:
This class is missing the `extract_state_from_offline_df` method, which is invoked by
offline_trainer.py. Running train_offline.py will crash with an AttributeError until 
this method is added during the bug-fixing phase.
"""

import torch
from torch.distributions import Normal
from src.config import MAX_PACKET_SIZE, MAX_F2_SQ, RAW_CFG

class V2XAgent:
    """
    Advanced Multi-Objective Stochastic Policy Agent regulating both
    mitigation filtering thresholds and state-gated computational overhead.
    """
    def __init__(self, model):
        self.model = model
        r_cfg = RAW_CFG["reward_shaping"]
        self.sensitivity_threshold = r_cfg["anomaly_sensitivity_threshold"]
        self.w_active = r_cfg["active_attack_weights"]
        self.w_nominal = r_cfg["nominal_traffic_weights"]

    def build_state_tensor(self, avg_size, avg_sq, anomaly_rate):
        """
        Constructs normalized 3-dimensional state Tensor.
        Dimensions: [Average Packet Size, Average F2 Sum Square, Anomaly Density Rate]
        """
        norm_size = avg_size / MAX_PACKET_SIZE
        norm_sq = avg_sq / MAX_F2_SQ
        return torch.tensor([norm_size, norm_sq, anomaly_rate], dtype=torch.float32)

    def extract_state_from_offline_df(self, df_slice):
        """
        Parses window matrix slices from offline CSV files into a state tensor.
        """
        avg_size = df_slice["packet_size"].mean()
        avg_sq = df_slice["max_sum_sq"].mean()
        anomaly_rate = df_slice["is_anomalous"].mean()
        return self.build_state_tensor(avg_size, avg_sq, anomaly_rate)

    def get_action_distribution(self, state_tensor):
        """
        Queries policy network to parameterize the Gaussian policy action distribution.
        """
        action_mean, state_value = self.model(state_tensor)
        action_std = torch.exp(self.model.log_std)
        return Normal(action_mean, action_std), state_value

    def compute_surrogate_reward(self, action_values, anomaly_rate, current_budget):
        """
        Multi-objective MDP formulation balancing computational overhead against FSM safety.
        
        Action Space Mappings:
        - action_values[0]: Recovery rate multiplier -> Rescaled to [0.0, 0.5]
        - action_values[1]: Penalty factor multiplier -> Rescaled to [0.0, 100.0]
        - action_values[2]: F2 similarity threshold -> Rescaled to [400, 800]
        """
        pred_recovery = action_values[0] * 0.5
        pred_penalty  = action_values[1] * 100.0
        pred_sq_thresh = 400 + (action_values[2] * 400)
        
        # S0 peacetime sampling rate is a continuous heuristic and no longer trained
        pred_base_sampling = 0.05
        
        if anomaly_rate > self.sensitivity_threshold:
            # Mitigation Phase: Reward high penalty actions but keep tracking budget depletion risks
            reward = (
                (pred_penalty * self.w_active["penalty_scale"]) + 
                (600.0 - pred_sq_thresh) * self.w_active["sq_thresh_scale"] - 
                (1.0 - current_budget / 100.0) * self.w_active["budget_violation_scale"]
            )
        else:
            # Nominal Phase: Reward low latency profiles by heavily penalizing unnecessary high sampling rates
            reward = (
                (pred_recovery * self.w_nominal["recovery_scale"]) + 
                (pred_sq_thresh - 600.0) * self.w_nominal["sq_overhead_scale"] -
                (pred_base_sampling * self.w_nominal["overhead_penalty_scale"]) # Execution penalty curve
            )
            
        return reward