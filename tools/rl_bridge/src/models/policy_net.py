"""
@file policy_net.py
@brief Actor-Critic Neural Network architecture for V2X FSM parameter regulation.

This module defines the PyTorch neural network architecture representing the
DRL agent's brain. It constructs a dynamic shared feature extraction torso feeding 
into two distinct heads (Actor and Critic).
"""

from typing import List, Tuple
import torch
import torch.nn as nn
from src.config import RAW_CFG

class DefencePolicyNet(nn.Module):
    """
    Actor-Critic Neural Network Topology for V2X FSM Parameter Regulation.
    Dynamically binds input/action dimensions and layer depths from global config.
    """
    def __init__(self, input_dim: int = None, action_dim: int = None, hidden_layers: List[int] = None):
        super(DefencePolicyNet, self).__init__()
        
        cfg = RAW_CFG
        # Automatically pull dimensions/layers from global YAML configuration if not specified
        if input_dim is None:
            input_dim = cfg["hyperparameters"]["input_dim"]
        if action_dim is None:
            action_dim = len(cfg["action_space"]["rl_controlled_actions"])
        if hidden_layers is None:
            hidden_layers = cfg.get("models", {}).get("hidden_layers", [64, 64])
        
        # Dynamic construction of MLP shared feature extraction torso
        layers = []
        prev_dim = input_dim
        for h_dim in hidden_layers:
            layers.append(nn.Linear(prev_dim, h_dim))
            layers.append(nn.ReLU())
            prev_dim = h_dim
            
        self.shared_layer = nn.Sequential(*layers)
        
        # Last hidden dimension index of the torso
        last_hidden_dim = hidden_layers[-1] if len(hidden_layers) > 0 else input_dim
        
        # Actor head: Outputs mean vector (mu) for Gaussian policy distribution, normalized via Sigmoid to [0, 1]
        self.actor_head = nn.Sequential(
            nn.Linear(last_hidden_dim, action_dim),
            nn.Sigmoid()
        )
        
        # Critic head: Outputs scalar state value V(s) to guide policy gradient direction
        self.critic_head = nn.Linear(last_hidden_dim, 1)
        
        # Trainable log standard deviation parameter for stochastic continuous exploration.
        # Initialized to -1.0 corresponding to exp(-1) ~= 0.368 baseline standard deviation.
        self.log_std = nn.Parameter(torch.zeros(action_dim) - 1.0)

    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Executes a synchronized parallel forward pass across both network heads.
        """
        features = self.shared_layer(x)
        action_mean = self.actor_head(features)
        state_value = self.critic_head(features)
        return action_mean, state_value