"""
@file base_env.py
@brief Abstract base class for the V2X reinforcement learning environment interface.

This module defines the template interface containing standard reinforcement learning 
methods (reset, step) matching Gymnasium API concepts.
"""

from abc import ABC, abstractmethod
from typing import Tuple, Dict, Any
import torch

class BaseV2XEnv(ABC):
    """
    Abstract Base class for V2X Reinforcement Learning environments.
    Guarantees standard Gym-like signatures.
    """
    
    @abstractmethod
    def reset(self) -> torch.Tensor:
        """
        Resets the environment state and returns the initial state tensor.
        
        @return torch.Tensor The initial normalized state observation.
        """
        pass
        
    @abstractmethod
    def step(self, action: torch.Tensor) -> Tuple[torch.Tensor, float, bool, Dict[str, Any]]:
        """
        Steps the environment using the provided action.
        
        @param action torch.Tensor The action tensor to execute.
        @return Tuple containing:
            - next_state (torch.Tensor)
            - reward (float)
            - done (bool)
            - info (Dict[str, Any])
        """
        pass
