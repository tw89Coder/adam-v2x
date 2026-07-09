"""
@file wrappers.py
@brief Gymnasium-style environment wrappers for state representation transformations.
"""

import collections
from typing import Tuple, Dict, Any
import torch

from src.envs.base_env import BaseV2XEnv

class FrameStackWrapper(BaseV2XEnv):
    """
    Decoupled Environment Wrapper that stacks the last k observations.
    Allows easy stateless/stateful toggling.
    """
    def __init__(self, env: BaseV2XEnv, k: int):
        """
        @param env The base environment instance to wrap.
        @param k The number of frames to stack.
        """
        self.env = env
        self.k = k
        self.frames = collections.deque(maxlen=k)
        
        # Mirror internal attributes for registry/builder compatibility
        if hasattr(env, "active_features"):
            self.active_features = env.active_features
        if hasattr(env, "action_space"):
            self.action_space = env.action_space

    def __getattr__(self, name: str) -> Any:
        """
        Dynamically delegates attribute lookups to the wrapped inner environment.
        Ensures compatibility with custom attributes (e.g. env.num_windows).
        """
        return getattr(self.env, name)

    @property
    def state_dim(self) -> int:
        """
        Returns the stacked observation feature space size.
        """
        base_dim = len(self.active_features) if hasattr(self, "active_features") else 3
        return base_dim * self.k

    def reset(self) -> torch.Tensor:
        """
        Resets base environment and populates frame queue with repeated initial state.
        """
        state = self.env.reset()
        self.frames.clear()
        # Initialize queue by repeating the first observation k times
        for _ in range(self.k):
            self.frames.append(state)
        return self._get_stacked_state()

    def step(self, action: Any) -> Tuple[torch.Tensor, float, bool, Dict[str, Any]]:
        """
        Steps base environment, appends observation, and returns stacked tensor.
        """
        next_state, reward, done, info = self.env.step(action)
        self.frames.append(next_state)
        return self._get_stacked_state(), reward, done, info

    def _get_stacked_state(self) -> torch.Tensor:
        """
        Concatenates all frames in queue into a single flat 1D Tensor.
        """
        return torch.cat(list(self.frames), dim=0)

    def close(self):
        """
        Closes base environment.
        """
        if hasattr(self.env, "close"):
            self.env.close()
