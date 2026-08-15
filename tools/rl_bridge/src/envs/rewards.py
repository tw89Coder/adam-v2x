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
    DQN reward with Lagrangian-style adaptive constraint penalty.
    Objective: minimize inspection overhead.
    Constraint: keep leakage_rate below leakage_target.
    """
    def __init__(
        self,
        lambda_penalty: float = None,
        lambda_lr: float = None,
        leakage_target: float = None,
        overhead_scale: float = None,
        security_horizon_windows: int = None,
        lambda_min: float = None,
        lambda_max: float = None,
    ):
        from collections import deque
        from src.config import RAW_CFG
        dqn_r = RAW_CFG.get("dqn", {}).get("reward_shaping", {})

        self.lambda_penalty = (
            lambda_penalty
            if lambda_penalty is not None
            else dqn_r.get("lambda_penalty", 10.0)
        )
        self.lambda_lr = (
            lambda_lr
            if lambda_lr is not None
            else dqn_r.get("lambda_lr", 0.05)
        )
        self.leakage_target = (
            leakage_target
            if leakage_target is not None
            else dqn_r.get("leakage_target", 0.01)
        )
        self.overhead_scale = (
            overhead_scale
            if overhead_scale is not None
            else dqn_r.get("overhead_scale", 2.0)
        )
        self.lambda_min = float(lambda_min if lambda_min is not None else dqn_r.get("lambda_min", 5.0))
        self.lambda_max = float(lambda_max if lambda_max is not None else dqn_r.get("lambda_max", 30.0))
        horizon = (
            security_horizon_windows
            if security_horizon_windows is not None
            else dqn_r.get("security_horizon_windows", 100)
        )
        self.security_counts = deque(maxlen=max(1, int(horizon)))
        self.last_rolling_leakage_rate = 0.0
        self.last_rolling_malware_count = 0

    def compute(self, metrics: dict, action_policy: list) -> float:
        tp = int(metrics.get("tp_count", 0))
        fn = int(metrics.get("fn_count", 0))
        self.security_counts.append((tp, fn))
        rolling_tp = sum(pair[0] for pair in self.security_counts)
        rolling_fn = sum(pair[1] for pair in self.security_counts)
        rolling_malware = rolling_tp + rolling_fn
        leakage_rate = rolling_fn / rolling_malware if rolling_malware > 0 else 0.0
        self.last_rolling_leakage_rate = leakage_rate
        self.last_rolling_malware_count = rolling_malware
        # The action controls the S0 base rate. Extra work imposed by the FSM
        # in S1--S3 is a safety intervention, so charging all of it to the
        # action gives the learner incorrect credit assignment.
        base_rate = metrics.get("base_sampling_rate", 0.0)
        inspect_rate = metrics.get("actual_inspection_rate", base_rate)

        violation = max(0.0, leakage_rate - self.leakage_target)

        reward = (
            -self.overhead_scale * (base_rate + 0.10 * inspect_rate)
            -self.lambda_penalty * violation
        )

        return float(reward)

    def reset(self):
        self.security_counts.clear()
        self.last_rolling_leakage_rate = 0.0
        self.last_rolling_malware_count = 0

    def update_lambda(self, avg_leakage_rate: float, malware_count: int = None):
        evidence = self.last_rolling_malware_count if malware_count is None else int(malware_count)
        # An empty horizon has no FNR evidence. It must not be interpreted as
        # zero leakage, which would erase the safety multiplier in peacetime.
        if evidence <= 0:
            return self.lambda_penalty
        self.lambda_penalty = min(
            self.lambda_max,
            max(
            self.lambda_min,
            self.lambda_penalty
            + self.lambda_lr * (avg_leakage_rate - self.leakage_target)
            )
        )
        return self.lambda_penalty
    
    
# class DqnSamplingReward(RewardStrategy):
#     """
#     DQN specific reward strategy.
#     Measures the absolute trade-off between security (true anomaly rate vs. detected anomalies) 
#     and performance (computational overhead of packet inspections).
#     """
#     def __init__(self, penalty_scale: float = None, overhead_scale: float = None):
#         from src.config import RAW_CFG
#         dqn_r = RAW_CFG.get("dqn", {}).get("reward_shaping", {})
#         self.penalty_scale = penalty_scale if penalty_scale is not None else dqn_r.get("penalty_scale", 10.0)
#         self.overhead_scale = overhead_scale if overhead_scale is not None else dqn_r.get("overhead_scale", 2.0)

#     def compute(self, metrics: dict, action_policy: list) -> float:
#         # Penalty for leaking malware packets (leakage rate is FN / (FN + TP))
#         leakage_rate = metrics["leakage_rate"]
        
#         # Overhead cost of inspecting packets (instant sampling rate)
#         inspect_rate = metrics["instant_sampling_rate"]
        
#         # Compute multi-objective reward

#         #REWARD SHAPING STRATEGY:
#         #reward = - (leakage_rate * self.penalty_scale + inspect_rate * self.overhead_scale)


#         reward = -inspect_rate - lambda_penalty * max(0.0, leakage_rate - 0.01)
#         return float(reward)
