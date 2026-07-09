"""
@file dqn_net.py
@brief PyTorch Q-Network model for Value-based Deep Q-Learning (DQN).
"""

import torch
import torch.nn as nn

class DQNNet(nn.Module):
    """
    Multilayer Perceptron (MLP) mapping observations to action Q-values.
    """
    def __init__(self, state_dim: int = 3, action_dim: int = 5, hidden_dim: int = None):
        """
        @param state_dim Dimension of observation space (default 3: sampling_rate, avg_sq, anomaly_rate).
        @param action_dim Number of discrete actions (default 5).
        @param hidden_dim Width of hidden dense layers.
        """
        super(DQNNet, self).__init__()
        if hidden_dim is None:
            from src.config import RAW_CFG
            hidden_dim = RAW_CFG.get("dqn", {}).get("hidden_dim", 64)
            
        self.net = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, action_dim)
        )
        
    def forward(self, state: torch.Tensor) -> torch.Tensor:
        """
        Executes forward pass to estimate Q-value arrays.
        """
        return self.net(state)
