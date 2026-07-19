"""Categorical PPO agent using the same discrete action semantics as DQN."""

from typing import Any, Tuple

import torch
from torch.distributions import Categorical

from src.agents.base_agent import BaseV2XAgent


class DiscretePPOAgent(BaseV2XAgent):
    """Samples one of the DQN action indices from a categorical policy."""

    algorithm_name = "discrete_ppo"

    def __init__(self, model: torch.nn.Module, action_translator: Any):
        self.model = model
        self.action_translator = action_translator
        self.explore = True

    def get_action_distribution(
        self, state_tensor: torch.Tensor
    ) -> Tuple[Categorical, torch.Tensor]:
        device = next(self.model.parameters()).device
        logits, value = self.model(state_tensor.to(device))
        return Categorical(logits=logits), value

    def act(self, state_tensor: torch.Tensor):
        dist, state_value = self.get_action_distribution(state_tensor)
        action = dist.sample() if self.explore else dist.probs.argmax(dim=-1)
        log_prob = dist.log_prob(action)
        action_index = int(action.item())

        raw_actions = [action_index]
        safe_actions = action_index
        return (
            action.detach().cpu(),
            (raw_actions, safe_actions),
            log_prob.detach().cpu(),
            state_value.detach().cpu(),
        )
