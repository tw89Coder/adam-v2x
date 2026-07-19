"""DQN-equivalent action and reward components isolated for discrete PPO."""

from typing import Any

try:
    from gymnasium import spaces
except ImportError:
    from gym import spaces


class DiscretePPOActionTranslator:
    """Copy of the DQN five-action sampling-rate translator."""

    def __init__(self, action_map: list = None):
        from src.config import RAW_CFG

        dqn_cfg = RAW_CFG.get("dqn", {})
        self.action_map = action_map or list(
            dqn_cfg.get("action_map", [-0.10, -0.05, 0.0, 0.05, 0.10])
        )

    def translate(self, action: Any, current_sampling_rate: float) -> list:
        action_index = max(0, min(len(self.action_map) - 1, int(action)))
        new_rate = max(
            0.05,
            min(1.0, current_sampling_rate + self.action_map[action_index]),
        )
        return [0.05, 50.0, 600, new_rate]

    def get_action_space(self) -> Any:
        return spaces.Discrete(len(self.action_map))


class DiscretePPOConstrainedReward:
    """Copy of the DQN Lagrangian constrained sampling reward."""

    def __init__(
        self,
        lambda_penalty: float = None,
        lambda_lr: float = None,
        leakage_target: float = None,
        overhead_scale: float = None,
    ):
        from src.config import RAW_CFG

        reward_cfg = RAW_CFG.get("dqn", {}).get("reward_shaping", {})
        self.lambda_penalty = (
            lambda_penalty
            if lambda_penalty is not None
            else reward_cfg.get("lambda_penalty", 10.0)
        )
        self.lambda_lr = (
            lambda_lr if lambda_lr is not None else reward_cfg.get("lambda_lr", 0.05)
        )
        self.leakage_target = (
            leakage_target
            if leakage_target is not None
            else reward_cfg.get("leakage_target", 0.01)
        )
        self.overhead_scale = (
            overhead_scale
            if overhead_scale is not None
            else reward_cfg.get("overhead_scale", 2.0)
        )

    def compute(self, metrics: dict, action_policy: list) -> float:
        del action_policy
        leakage_rate = metrics["leakage_rate"]
        inspection_rate = metrics["instant_sampling_rate"]
        violation = max(0.0, leakage_rate - self.leakage_target)
        return float(
            -self.overhead_scale * inspection_rate
            -self.lambda_penalty * violation
        )

    def update_lambda(self, avg_leakage_rate: float) -> float:
        self.lambda_penalty = max(
            0.0,
            self.lambda_penalty
            + self.lambda_lr * (avg_leakage_rate - self.leakage_target),
        )
        return self.lambda_penalty
