"""
@file base_learner.py
@brief Abstract base class for Reinforcement Learning training/optimization algorithms.

This module exposes the interface matching the optimization controller of RL policies.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List
import torch

class BaseLearner(ABC):
    """
    Abstract Base Learner class for policy optimization.
    """
    
    @abstractmethod
    def update(self, trajectory_buffer: Dict[str, List[torch.Tensor]]) -> Dict[str, float]:
        """
        Executes a gradient optimization pass using collected trajectories.
        
        @param trajectory_buffer Dictionary containing keys:
            - 'states' (List[torch.Tensor])
            - 'actions' (List[torch.Tensor])
            - 'log_probs' (List[torch.Tensor])
            - 'rewards' (List[torch.Tensor])
            - 'values' (List[torch.Tensor])
            - 'next_states' (List[torch.Tensor])
        @return Dict[str, float] Training metrics logged from this update.
        """
        pass
