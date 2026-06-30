"""
@file policy_net.py
@brief Actor-Critic Neural Network architecture for V2X FSM parameter regulation.

This module defines the PyTorch neural network architecture representing the
DRL agent's brain. It utilizes a shared feature extraction layer feeding into
two distinct heads:
1. An Actor head that outputs the mean vector (mu) of a Gaussian distribution 
   for continuous action sampling.
2. A Critic head that outputs the estimated value V(s) of the current state 
   context, used for computing on-policy advantages in PPO updates.
"""

import torch
import torch.nn as nn
from src.config import RAW_CFG

class DefencePolicyNet(nn.Module):
    """
    Actor-Critic Neural Network Topology for V2X FSM Parameter Regulation.
    Dynamically binds input and action dimensions from the global YAML matrix.
    """
    def __init__(self, input_dim=None, action_dim=None, hidden_dim=64):
        super(DefencePolicyNet, self).__init__()
        
        # Automatically pull dimensions from global YAML configuration if not specified
        if input_dim is None:
            input_dim = RAW_CFG["hyperparameters"]["input_dim"]
        if action_dim is None:
            action_dim = RAW_CFG["hyperparameters"]["action_dim"]
        
        # Shared feature representation layer (multi-layer perceptron feature extractor)
        self.shared_layer = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU()
        )
        
        # Actor head: Outputs mean (mu) for Gaussian policy distribution, normalized via Sigmoid to [0, 1]
        self.actor_head = nn.Sequential(
            nn.Linear(hidden_dim, action_dim),
            nn.Sigmoid()
        )
        
        # Critic head: Outputs scalar state value V(s) to guide policy gradient direction
        self.critic_head = nn.Linear(hidden_dim, 1)
        
        # Trainable log standard deviation parameter for stochastic continuous exploration.
        # Initialized to -1.0 corresponding to exp(-1) ~= 0.368 baseline standard deviation.
        self.log_std = nn.Parameter(torch.zeros(action_dim) - 1.0)

    def forward(self, x):
        """
        Executes a synchronized parallel forward pass across both network heads.
        """
        features = self.shared_layer(x)
        action_mean = self.actor_head(features)
        state_value = self.critic_head(features)
        return action_mean, state_value