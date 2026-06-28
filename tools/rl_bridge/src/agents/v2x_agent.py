# src/agents/v2x_agent.py
import torch
from torch.distributions import Normal
from src.config import MAX_PACKET_SIZE, MAX_F2_SQ, RAW_CFG

class V2XAgent:
    """
    Encapsulates stochastic policy execution, log-probability tracking,
    and mathematical reward shaping driven dynamically via external YAML parameters.
    """
    def __init__(self, model):
        self.model = model
        
        # Ingest dynamic reward shaping matrices directly from the loaded YAML configuration
        r_cfg = RAW_CFG["reward_shaping"]
        self.sensitivity_threshold = r_cfg["anomaly_sensitivity_threshold"]
        
        self.w_active = r_cfg["active_attack_weights"]
        self.w_nominal = r_cfg["nominal_traffic_weights"]

    def build_state_tensor(self, avg_size, avg_sq, anomaly_rate):
        """
        Unified Feature Engineering Engine to eliminate Feature Skew between Online and Offline environments.
        """
        norm_size = avg_size / MAX_PACKET_SIZE
        norm_sq = avg_sq / MAX_F2_SQ
        return torch.tensor([norm_size, norm_sq, anomaly_rate], dtype=torch.float32)

    def extract_state_from_offline_df(self, window_slice):
        """
        Offline Pipeline Utility: Extracts states from pandas DataFrame timelines.
        """
        avg_size = window_slice['packet_size'].mean()
        avg_sq = window_slice['max_sum_sq'].mean()
        anomaly_rate = window_slice['is_anomalous'].mean()       
        return self.build_state_tensor(avg_size, avg_sq, anomaly_rate)

    def get_action_distribution(self, state_tensor):
        """
        Constructs a continuous Gaussian distribution from network outputs.
        """
        action_mean, state_value = self.model(state_tensor)
        action_std = torch.exp(self.model.log_std)
        distribution = Normal(action_mean, action_std)
        return distribution, state_value

    def compute_surrogate_reward(self, action_values, anomaly_rate, current_budget):
        """
        Calculates the multi-scenario MDP reward utilizing parameters bound from the configuration layer.
        """
        pred_recovery = action_values[0] * 0.5
        pred_penalty  = action_values[1] * 100.0
        pred_sq_thresh = 400 + (action_values[2] * 400)
        
        # Use dynamic sensitivity mapping configured externally (e.g. 0.005 to catch 1% spikes)
        if anomaly_rate > self.sensitivity_threshold:
            # Mitigation Phase: Bound by penalty scales, threshold minimization targets, and budget state drops
            reward = (
                (pred_penalty * self.w_active["penalty_scale"]) + 
                (600.0 - pred_sq_thresh) * self.w_active["sq_thresh_scale"] - 
                (1.0 - current_budget / 100.0) * self.w_active["budget_violation_scale"]
            )
        else:
            # Nominal Phase: Optimize for continuous transmission capabilities
            reward = (
                (pred_recovery * self.w_nominal["recovery_scale"]) + 
                (pred_sq_thresh - 600.0) * self.w_nominal["sq_overhead_scale"]
            )
            
        return reward