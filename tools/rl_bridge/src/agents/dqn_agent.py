"""
@file dqn_agent.py
@brief Value-based DQN Agent wrapper managing epsilon-greedy action selection and translation.
"""

import math
import random
from typing import Tuple, Any
import torch

from src.agents.base_agent import BaseV2XAgent

class DQNAgent(BaseV2XAgent):
    """
    Epsilon-greedy exploration Agent wrapper for DQN models.
    Provides identical act() signature to maintain compatibility with PPO co-simulation loops.
    """
    def __init__(self, model: torch.nn.Module, action_translator: Any, eps_start: float = None, eps_end: float = None, eps_decay: int = None):
        """
        @param model The PyTorch Q-Network model.
        @param action_translator The translator mapping discrete actions to FSM parameters.
        @param eps_start Starting exploration probability.
        @param eps_end Minimum exploration probability.
        @param eps_decay Epsilon decay rate step divisor.
        """
        from src.config import RAW_CFG
        dqn_cfg = RAW_CFG.get("dqn", {})
        
        self.model = model
        self.action_translator = action_translator
        self.explore = True  # Set to False during production serving / evaluation
        
        self.eps_start = eps_start if eps_start is not None else dqn_cfg.get("eps_start", 1.0)
        self.eps_end = eps_end if eps_end is not None else dqn_cfg.get("eps_end", 0.05)
        self.eps_decay = eps_decay if eps_decay is not None else dqn_cfg.get("eps_decay", 1000)
        self.steps_done = 0
        
    def act(self, state_tensor: torch.Tensor) -> Tuple[torch.Tensor, Tuple[list, Any], torch.Tensor, torch.Tensor]:
        """
        Epsilon-greedy action selection method.
        Matches the act() signature of V2XAgent.
        """
        self.steps_done += 1
        eps_threshold = self.eps_end + (self.eps_start - self.eps_end) * \
                        math.exp(-1. * self.steps_done / self.eps_decay)
        
        action_dim = self.model.net[-1].out_features if hasattr(self.model, 'net') else 5
        
        if self.explore and random.random() < eps_threshold:
            action_idx = random.randint(0, action_dim - 1)
        else:
            with torch.no_grad():
                # Cast the state tensor to the hardware device of the network parameters
                device = next(self.model.parameters()).device
                q_values = self.model(state_tensor.to(device).unsqueeze(0))
                action_idx = q_values.argmax(dim=-1).item()
                
        action = torch.tensor([action_idx], dtype=torch.long)
        
        # To maintain compatibility with main.py run loops:
        # raw_actions is a list of features, safe_actions is the discrete index.
        # V2XOnlineSocketEnv.step will receive the discrete index (safe_actions) and translate it.
        raw_actions = [action_idx]
        safe_actions = action_idx
        
        # Dummy variables to satisfy PPO expectation signatures
        log_prob = torch.zeros(1)
        state_value = torch.zeros(1)
        
        return action, (raw_actions, safe_actions), log_prob, state_value
