"""
@file base_agent.py
@brief Abstract base class for the Reinforcement Learning agent.

This module defines standard interface methods for forward inference and action selection.
"""

from abc import ABC, abstractmethod
from typing import Tuple, Any
import torch

class BaseV2XAgent(ABC):
    """
    Abstract Base class for V2X Agent wrappers.
    """
    
    @abstractmethod
    def act(self, state_tensor: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Samples an action from the policy distribution given the state observation.
        
        @param state_tensor torch.Tensor The current environment state tensor.
        @return Tuple containing:
            - sampled_action (torch.Tensor) Clamped/unclamped raw action tensor.
            - action_for_env (torch.Tensor) Action mapped ready for the environment.
            - log_prob (torch.Tensor) Log probability of the sampled action.
        """
        pass
