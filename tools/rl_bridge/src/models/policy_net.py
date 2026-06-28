# src/models/policy_net.py
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
        
        # Shared feature representation layer
        self.shared_layer = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU()
        )
        
        # Actor head: Outputs mean (mu) for Gaussian policy distribution
        self.actor_head = nn.Sequential(
            nn.Linear(hidden_dim, action_dim),
            nn.Sigmoid()
        )
        
        # Critic head: Outputs scalar state value V(s)
        self.critic_head = nn.Linear(hidden_dim, 1)
        
        # Trainable log standard deviation parameter for stochastic continuous exploration
        self.log_std = nn.Parameter(torch.zeros(action_dim) - 1.0)

    def forward(self, x):
        """
        Executes a synchronized parallel forward pass across both network heads.
        """
        features = self.shared_layer(x)
        action_mean = self.actor_head(features)
        state_value = self.critic_head(features)
        return action_mean, state_value