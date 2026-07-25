"""
@file translators.py
@brief Action translation strategy classes mapping RL agent actions to C++ FSM parameter structures.
"""

from typing import Any

try:
    from gymnasium import spaces
except ImportError:
    from gym import spaces

class ActionTranslator:
    def translate(self, action: Any, current_sampling_rate: float) -> list:
        """
        Translates raw agent action to C++ 4D policy array:
        [recovery_rate, penalty_multiplier, sq_threshold, base_sampling_rate]
        """
        raise NotImplementedError

    def get_action_space(self) -> Any:
        """
        Returns Gym-style Action Space instance.
        """
        raise NotImplementedError


class PpoActionTranslator(ActionTranslator):
    """
    Pass-through translator for PPO continuous action spaces.
    PPO already outputs a 4D array matching FSM parameter layouts.
    """
    def translate(self, action: Any, current_sampling_rate: float) -> list:
        if isinstance(action, (list, tuple)) and len(action) == 4:
            return list(action)
        return list(action)  # Fallback directly

    def get_action_space(self) -> Any:
        import numpy as np
        return spaces.Box(
            low=np.array([0.001, 1.0, 400.0, 0.0], dtype=np.float32),
            high=np.array([0.5, 100.0, 800.0, 1.0], dtype=np.float32),
            dtype=np.float32
        )


class DqnActionTranslator(ActionTranslator):
    """
    Translator for DQN discrete action spaces.
    Maps a discrete action index (0-4) to a change in FSM base sampling rate.
    """
    def __init__(self, action_map: list = None):
        from src.config import RAW_CFG
        dqn_cfg = RAW_CFG.get("dqn", {})
        # Read maps from central configuration
        self.action_map = action_map or dqn_cfg.get("action_map", [-0.20, -0.10, 0.0, 0.10, 0.20])

    def translate(self, action: Any, current_sampling_rate: float) -> list:
        action_index = int(action)
        # Ensure index safety bounds
        action_index = max(0, min(len(self.action_map) - 1, action_index))
        delta = self.action_map[action_index]
        
        # Calculate new sampling rate, clamp between [0.05, 1.0] to maintain baseline FSM responsiveness
        new_rate = max(0.05, min(1.0, current_sampling_rate + delta))
        
        # Return 4D policy: [recovery_rate, penalty_multiplier, sq_threshold, new_sampling_rate]
        # Rest of the parameters are set to default baseline FSM settings
        return [0.05, 50.0, 600, new_rate]

    def get_action_space(self) -> Any:
        return spaces.Discrete(len(self.action_map))
