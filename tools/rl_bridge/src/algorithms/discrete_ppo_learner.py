"""DQN-aligned categorical PPO learner with GAE and clipped updates."""

from typing import Any, Dict, List

import torch
import torch.nn as nn
import torch.optim as optim

from src.algorithms.base_learner import BaseLearner
from src.config import RAW_CFG


class DiscretePPOLearner(BaseLearner):
    """On-policy PPO-Clip optimizer for a categorical action distribution."""

    def __init__(self, agent: Any, lr: float = 0.0003):
        self.agent = agent
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.agent.model.to(self.device)

        common_cfg = RAW_CFG.get("hyperparameters", {})
        cfg = RAW_CFG.get("discrete_ppo", {})
        self.gamma = cfg.get("gamma", common_cfg.get("gamma", 0.99))
        self.gae_lambda = cfg.get("gae_lambda", 0.95)
        self.clip_eps = cfg.get("clip_eps", common_cfg.get("clip_eps", 0.2))
        self.update_epochs = cfg.get("update_epochs", 10)
        self.minibatch_size = cfg.get("minibatch_size", 64)
        self.value_coef = cfg.get("value_coef", 0.5)
        self.entropy_coef = cfg.get("entropy_coef", 0.01)
        self.max_grad_norm = cfg.get("max_grad_norm", 0.5)
        self.optimizer = optim.Adam(self.agent.model.parameters(), lr=lr)

    def update(self, trajectory_buffer: Dict[str, List[torch.Tensor]]) -> Dict[str, float]:
        states = torch.stack(trajectory_buffer["states"]).to(self.device)
        actions = torch.stack(trajectory_buffer["actions"]).long().view(-1).to(self.device)
        old_log_probs = torch.stack(trajectory_buffer["log_probs"]).view(-1).to(self.device)
        rewards = torch.stack(trajectory_buffer["rewards"]).view(-1).to(self.device)
        old_values = torch.stack(trajectory_buffer["values"]).view(-1).to(self.device)
        next_states = torch.stack(trajectory_buffer["next_states"]).to(self.device)
        dones = torch.stack(trajectory_buffer["dones"]).view(-1).to(self.device)

        with torch.no_grad():
            _, next_values = self.agent.model(next_states)
            deltas = rewards + self.gamma * next_values * (1.0 - dones) - old_values
            advantages = torch.zeros_like(rewards)
            gae = torch.zeros((), device=self.device)
            for index in reversed(range(len(rewards))):
                gae = (
                    deltas[index]
                    + self.gamma
                    * self.gae_lambda
                    * (1.0 - dones[index])
                    * gae
                )
                advantages[index] = gae
            returns = advantages + old_values
            advantages = (advantages - advantages.mean()) / (
                advantages.std(unbiased=False) + 1e-8
            )

        actor_total = critic_total = entropy_total = total_total = 0.0
        updates = 0
        sample_count = len(states)

        for _ in range(self.update_epochs):
            indices = torch.randperm(sample_count, device=self.device)
            for start in range(0, sample_count, self.minibatch_size):
                batch = indices[start : start + self.minibatch_size]
                dist, values = self.agent.get_action_distribution(states[batch])
                new_log_probs = dist.log_prob(actions[batch])
                entropy = dist.entropy().mean()

                ratios = torch.exp(new_log_probs - old_log_probs[batch])
                unclipped = ratios * advantages[batch]
                clipped = torch.clamp(
                    ratios, 1.0 - self.clip_eps, 1.0 + self.clip_eps
                ) * advantages[batch]
                actor_loss = -torch.min(unclipped, clipped).mean()
                critic_loss = nn.functional.mse_loss(values, returns[batch])
                total_loss = (
                    actor_loss
                    + self.value_coef * critic_loss
                    - self.entropy_coef * entropy
                )

                self.optimizer.zero_grad()
                total_loss.backward()
                nn.utils.clip_grad_norm_(self.agent.model.parameters(), self.max_grad_norm)
                self.optimizer.step()

                actor_total += actor_loss.item()
                critic_total += critic_loss.item()
                entropy_total += entropy.item()
                total_total += total_loss.item()
                updates += 1

        divisor = max(updates, 1)
        return {
            "actor_loss": actor_total / divisor,
            "critic_loss": critic_total / divisor,
            "entropy": entropy_total / divisor,
            "total_loss": total_total / divisor,
        }


from src.utils.registry import register_algorithm


@register_algorithm("discrete_ppo")
def build_discrete_ppo_pipeline(
    lr: float,
    port: int,
    mode: str,
    raw_data=None,
    frame_stack: int = 1,
    **kwargs,
):
    from src.agents.discrete_ppo_agent import DiscretePPOAgent
    from src.envs.discrete_ppo_components import (
        DiscretePPOActionTranslator,
        DiscretePPOConstrainedReward,
    )
    from src.envs.offline_dataset_env import V2XOfflineDatasetEnv
    from src.envs.online_socket_env import V2XOnlineSocketEnv
    from src.models.discrete_ppo_net import DiscretePPOActorCritic

    translator = DiscretePPOActionTranslator()
    reward_strategy = DiscretePPOConstrainedReward()
    if mode == "online":
        env = V2XOnlineSocketEnv(
            port=port,
            action_translator=translator,
            reward_strategy=reward_strategy,
        )
    else:
        env = V2XOfflineDatasetEnv(
            raw_data=raw_data,
            action_translator=translator,
            reward_strategy=reward_strategy,
        )

    if frame_stack > 1:
        from src.envs.wrappers import FrameStackWrapper

        env = FrameStackWrapper(env, k=frame_stack)

    state_dim = env.state_dim if hasattr(env, "state_dim") else 3
    action_dim = translator.get_action_space().n
    model = DiscretePPOActorCritic(state_dim=state_dim, action_dim=action_dim)
    agent = DiscretePPOAgent(model, action_translator=translator)
    learner = DiscretePPOLearner(agent, lr=lr)
    return env, agent, learner
