"""Discrete actor-critic network used by the DQN-aligned PPO experiment."""

from typing import Tuple

import torch
import torch.nn as nn

from src.config import RAW_CFG


class DiscretePPOActorCritic(nn.Module):
    """Shared MLP torso with categorical actor logits and a scalar critic."""

    def __init__(self, state_dim: int, action_dim: int, hidden_dim: int = None):
        super().__init__()
        cfg = RAW_CFG.get("discrete_ppo", {})
        hidden_dim = hidden_dim or cfg.get("hidden_dim", 128)

        self.shared = nn.Sequential(
            nn.Linear(state_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.Tanh(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.Tanh(),
        )
        self.actor = nn.Linear(hidden_dim, action_dim)
        self.critic = nn.Linear(hidden_dim, 1)

    def forward(self, state: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        features = self.shared(state)
        return self.actor(features), self.critic(features).squeeze(-1)
