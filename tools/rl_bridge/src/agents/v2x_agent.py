# src/agents/v2x_agent.py
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
        norm_size = avg_size / MAX_PACKET_SIZE
        norm_sq = avg_sq / MAX_F2_SQ
        return torch.tensor([norm_size, norm_sq, anomaly_rate], dtype=torch.float32)

    def get_action_distribution(self, state_tensor):
        action_mean, state_value = self.model(state_tensor)
        action_std = torch.exp(self.model.log_std)
        return Normal(action_mean, action_std), state_value

    def compute_surrogate_reward(self, action_values, anomaly_rate, current_budget):
        """
        Multi-objective MDP formulation balancing computational overhead against FSM safety.
        """
        pred_recovery = action_values[0] * 0.5
        pred_penalty  = action_values[1] * 100.0
        pred_sq_thresh = 400 + (action_values[2] * 400)
        
        # Action[3] represents the dynamic AI-controlled sampling rate for State S0
        pred_s0_sampling = action_values[3] 
        
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
                (pred_s0_sampling * self.w_nominal["overhead_penalty_scale"]) # Execution penalty curve
            )
            
        return reward