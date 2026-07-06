"""
@file dqn_learner.py
@brief Value-based Deep Q-Network (DQN) optimization algorithm and replay buffers.
"""

import random
import math
from typing import Dict, List, Tuple, Any
import torch
import torch.nn as nn
import torch.optim as optim

from src.algorithms.base_learner import BaseLearner
from src.config import RAW_CFG

class TensorReplayBuffer:
    """
    High-performance ring-buffer experience replay using pre-allocated PyTorch Tensors.
    Prevents Garbage Collection (GC) latency jitter during high frequency runs.
    """
    def __init__(self, capacity: int, state_dim: int, device: str = "cpu"):
        self.capacity = capacity
        self.device = device
        self.ptr = 0
        self.size = 0
        
        # Pre-allocate layout structures in memory block
        self.states = torch.zeros((capacity, state_dim), dtype=torch.float32, device=device)
        self.actions = torch.zeros((capacity, 1), dtype=torch.long, device=device)
        self.rewards = torch.zeros((capacity, 1), dtype=torch.float32, device=device)
        self.next_states = torch.zeros((capacity, state_dim), dtype=torch.float32, device=device)
        self.dones = torch.zeros((capacity, 1), dtype=torch.float32, device=device)

    def push(self, state: torch.Tensor, action: int, reward: float, next_state: torch.Tensor, done: bool):
        self.states[self.ptr] = state
        self.actions[self.ptr] = torch.tensor([action], dtype=torch.long)
        self.rewards[self.ptr] = torch.tensor([reward], dtype=torch.float32)
        self.next_states[self.ptr] = next_state
        self.dones[self.ptr] = torch.tensor([float(done)], dtype=torch.float32)
        
        self.ptr = (self.ptr + 1) % self.capacity
        self.size = min(self.size + 1, self.capacity)

    def sample(self, batch_size: int) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        indices = torch.randint(0, self.size, (batch_size,))
        return (
            self.states[indices],
            self.actions[indices],
            self.rewards[indices],
            self.next_states[indices],
            self.dones[indices]
        )


class DQNLearner(BaseLearner):
    """
    Value-based Deep Q-Network Learner.
    Maintains target model weights, epsilon decay exploration parameters, and loss backprop.
    """
    def __init__(self, agent: Any, lr: float = 0.0005, eps_start: float = None, eps_end: float = None, eps_decay: int = None):
        """
        @param agent The DQNAgent instance containing the model.
        @param lr Learning rate for Adam optimizer.
        @param eps_start Starting exploration probability.
        @param eps_end Minimum exploration probability.
        @param eps_decay Epsilon decay speed step divisor.
        """
        self.agent = agent
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # Hyperparameters
        cfg = RAW_CFG.get("hyperparameters", {})
        dqn_cfg = RAW_CFG.get("dqn", {})
        
        self.gamma = cfg.get("gamma", 0.99)
        self.tau = dqn_cfg.get("tau", 0.005)
        self.batch_size = cfg.get("batch_size", 32)
        
        # Exploration variables
        self.eps_start = eps_start if eps_start is not None else dqn_cfg.get("eps_start", 1.0)
        self.eps_end = eps_end if eps_end is not None else dqn_cfg.get("eps_end", 0.05)
        self.eps_decay = eps_decay if eps_decay is not None else dqn_cfg.get("eps_decay", 1000)
        self.steps_done = 0
        
        # Move local policy agent network to specified hardware device
        self.agent.model.to(self.device)
        
        # Target network initialization for training stability
        import copy
        self.target_model = copy.deepcopy(self.agent.model).to(self.device)
        self.target_model.eval()
        
        # Optimizer
        self.optimizer = optim.Adam(self.agent.model.parameters(), lr=lr)
        self.loss_fn = nn.MSELoss()
        
        # Initialize Replay Buffer (Capacity: configured, State Dimension: dynamically read)
        state_dim = self.agent.model.net[0].in_features if hasattr(self.agent.model, 'net') else 3
        capacity = dqn_cfg.get("capacity", 10000)
        self.memory = TensorReplayBuffer(capacity=capacity, state_dim=state_dim, device=self.device)

    def select_action(self, state: torch.Tensor, explore: bool = True) -> int:
        """
        Epsilon-greedy exploration wrapper.
        """
        self.steps_done += 1
        eps_threshold = self.eps_end + (self.eps_start - self.eps_end) * \
                        math.exp(-1. * self.steps_done / self.eps_decay)
        
        if explore and random.random() < eps_threshold:
            # Stochastic random action selection (discrete choice 0 to 4)
            action_dim = self.agent.model.net[-1].out_features if hasattr(self.agent.model, 'net') else 5
            return random.randint(0, action_dim - 1)
        else:
            # Exploitative greedy selection
            with torch.no_grad():
                q_values = self.agent.model(state.to(self.device).unsqueeze(0))
                return q_values.argmax(dim=-1).item()

    def update(self, trajectory_buffer: Dict[str, List[torch.Tensor]]) -> Dict[str, float]:
        """
        Executes a Q-learning gradient step using a sampled batch from the replay buffer.
        """
        # 1. Push incoming trajectory buffer frames into the long-term Replay Buffer
        states = trajectory_buffer["states"]
        actions = trajectory_buffer["actions"]
        rewards = trajectory_buffer["rewards"]
        next_states = trajectory_buffer["next_states"]
        dones = trajectory_buffer["dones"]
        
        for idx in range(len(states)):
            self.memory.push(
                states[idx],
                actions[idx].item(),
                rewards[idx].item(),
                next_states[idx],
                dones[idx].item()
            )
            
        # 2. Wait until enough memories are collected
        if self.memory.size < self.batch_size:
            return {
                "q_loss": 0.0,
                "mean_q": 0.0,
                "mean_target_q": 0.0,
                "mean_reward": 0.0,
                "replay_size": float(self.memory.size),
                "skipped_update": 1.0,
            }
            #return {"loss": 0.0, "mean_q": 0.0}
            
        # 3. Sample batch from Replay Buffer
        b_states, b_actions, b_rewards, b_next_states, b_dones = self.memory.sample(self.batch_size)
        
        # 4. Compute current Q values: Q(s, a)
        q_values = self.agent.model(b_states)
        state_action_values = q_values.gather(1, b_actions)
        
        # 5. Compute Target Q values: Target = r + gamma * max_a Q_target(s', a) * (1 - done)
        with torch.no_grad():
            next_q_values = self.target_model(b_next_states)
            max_next_q_values = next_q_values.max(dim=1, keepdim=True)[0]
            expected_state_action_values = b_rewards + (self.gamma * max_next_q_values * (1.0 - b_dones))
            
        # 6. Compute loss and optimize network
        loss = self.loss_fn(state_action_values, expected_state_action_values)
        self.optimizer.zero_grad()
        loss.backward()
        self.optimizer.step()
        
        # 7. Soft Update target network weights: target = tau * model + (1 - tau) * target
        for target_param, local_param in zip(self.target_model.parameters(), self.agent.model.parameters()):
            target_param.data.copy_(self.tau * local_param.data + (1.0 - self.tau) * target_param.data)
            
        # Return metrics for console logging
        # To align with run_online logger, we output dummy actor/critic losses or mapping names

        # Return DQN-specific metrics for console logging
        return {
            "q_loss": loss.item(),
            "mean_q": state_action_values.mean().item(),
            "mean_target_q": expected_state_action_values.mean().item(),
            "mean_reward": b_rewards.mean().item(),
            "replay_size": float(self.memory.size),
        }
    
        # return {
        #     "actor_loss": loss.item(),
        #     "critic_loss": state_action_values.mean().item(),
        #     "loss": loss.item(),
        #     "mean_q": state_action_values.mean().item()
        # }


# ==============================================================================
# Pipeline Registration
# ==============================================================================
from src.utils.registry import register_algorithm

@register_algorithm("dqn")
def build_dqn_pipeline(lr: float, port: int, mode: str, raw_data=None, frame_stack: int = 1, **kwargs):
    """
    Dynamic DQN RL pipeline builder callback.
    """
    from src.models.dqn_net import DQNNet
    from src.agents.dqn_agent import DQNAgent
    from src.envs.online_socket_env import V2XOnlineSocketEnv
    from src.envs.offline_dataset_env import V2XOfflineDatasetEnv
    from src.envs.translators import DqnActionTranslator
    from src.envs.rewards import DqnSamplingReward
    
    translator = DqnActionTranslator()
    reward_strategy = DqnSamplingReward()
    
    if mode == "online":
        env = V2XOnlineSocketEnv(port=port, action_translator=translator, reward_strategy=reward_strategy)
    else:
        env = V2XOfflineDatasetEnv(raw_data=raw_data, action_translator=translator, reward_strategy=reward_strategy)
        
    if frame_stack > 1:
        from src.envs.wrappers import FrameStackWrapper
        env = FrameStackWrapper(env, k=frame_stack)
        
    state_dim = env.state_dim if hasattr(env, "state_dim") else (len(env.active_features) if hasattr(env, "active_features") else 3)
    action_dim = translator.get_action_space().n
    
    model = DQNNet(state_dim=state_dim, action_dim=action_dim)
    agent = DQNAgent(model, action_translator=translator)
    learner = DQNLearner(agent, lr=lr)
    return env, agent, learner

