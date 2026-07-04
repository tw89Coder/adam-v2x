"""
@file rewards.py
@brief Reward calculation strategy classes for PPO and DQN MDP objectives.
"""

class RewardStrategy:
    def compute(self, metrics: dict, action_policy: list) -> float:
        """
        Computes step reward based on co-simulation metrics and current policy actions.
        """
        raise NotImplementedError


class PpoSurrogateReward(RewardStrategy):
    """
    Legacy multi-objective surrogate reward matching PPO continuous optimization goals.
    Balances active attack penalty and nominal overhead constraints.
    """
    def __init__(self, sensitivity_threshold: float, w_active: dict, w_nominal: dict):
        self.sensitivity_threshold = sensitivity_threshold
        self.w_active = w_active
        self.w_nominal = w_nominal

    def compute(self, metrics: dict, action_policy: list) -> float:
        pred_recovery = action_policy[0]
        pred_penalty = action_policy[1]
        pred_sq_thresh = action_policy[2]
        pred_base_sampling = action_policy[3]
        
        anomaly_rate = metrics["anomaly_rate"]
        current_budget = metrics.get("avg_budget", 1.0) * 100.0  # Scale back to 0-100 for legacy compatibility
        
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


class DqnSamplingReward(RewardStrategy):
    """
    DQN specific reward strategy.
    Measures the absolute trade-off between security (true anomaly rate vs. detected anomalies) 
    and performance (computational overhead of packet inspections).
    """
    def __init__(self, penalty_scale: float = None, overhead_scale: float = None):
        from src.config import RAW_CFG
        dqn_r = RAW_CFG.get("dqn", {}).get("reward_shaping", {})
        self.penalty_scale = penalty_scale if penalty_scale is not None else dqn_r.get("penalty_scale", 10.0)
        self.overhead_scale = overhead_scale if overhead_scale is not None else dqn_r.get("overhead_scale", 2.0)

    def compute(self, metrics: dict, action_policy: list) -> float:
        # Penalty for leaking malware packets (leakage rate is FN / (FN + TP))
        leakage_rate = metrics["leakage_rate"]
        
        # Overhead cost of inspecting packets (instant sampling rate)
        inspect_rate = metrics["instant_sampling_rate"]
        
        # Compute multi-objective reward
        reward = - (leakage_rate * self.penalty_scale + inspect_rate * self.overhead_scale)
        return float(reward)
