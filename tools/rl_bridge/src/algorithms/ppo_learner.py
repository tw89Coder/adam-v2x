"""
@file ppo_learner.py
@brief Proximal Policy Optimization (PPO) training engine calculating actor and critic losses.

This module houses the PPOLearner, which isolates the mathematical updates of PPO
from the environment socket communications.
"""

from typing import Dict, List, Tuple, Any
import torch
import torch.nn as nn
import torch.optim as optim

from src.config import RAW_CFG
from src.algorithms.base_learner import BaseLearner

class PPOLearner(BaseLearner):
    """
    On-Policy Proximal Policy Optimization Optimizer.
    Manages actor-critic gradients, policy ratio constraints, and entropy scaling.
    """
    def __init__(self, agent: Any = None, lr: float = 0.0003):
        """
        @param agent The agent instance containing the model.
        @param lr Learning rate for the Adam optimizer.
        """
        self.agent = agent
        
        cfg = RAW_CFG["hyperparameters"]
        self.clip_eps = cfg["clip_eps"]
        self.gamma = cfg["gamma"]
        self.ppo_epochs = cfg["ppo_epochs_online"]
        
        # Instantiate localized optimizer targeting policy parameters
        self.optimizer = optim.Adam(self.agent.model.parameters(), lr=lr)

    def update(self, trajectory_buffer: Dict[str, List[torch.Tensor]]) -> Dict[str, float]:
        """
        ========================================================================
        PPO MATHEMATICAL UPDATE WALKTHROUGH & DOCUMENTATION
        ========================================================================
        This method performs the core Reinforcement Learning gradient updates.
        
        1. POLICY IMPORTANCE SAMPLING RATIO (r):
           Calculates the likelihood ratio between the new policy (under optimization)
           and the old policy (which collected the experience):
               r_t(theta) = pi_theta(a_t | s_t) / pi_theta_old(a_t | s_t)
               
        2. ACTOR LOSS (Policy Objective):
           PPO prevents the policy from updating too aggressively by clipping the ratio
           within [1 - epsilon, 1 + epsilon]:
               L_CLIP(theta) = -E[ min(r_t * A_t, clip(r_t, 1-eps, 1+eps) * A_t) ]
           * Advantage (A_t): Indicates whether the action performed better or worse
             than the average value predicted for that state.
             Positive Advantage -> Actor is pushed to increase action probability.
             Negative Advantage -> Actor is pushed to decrease action probability.
           
        3. CRITIC LOSS (Value Objective):
           Updates the state-value network to better predict expected return targets (V_target):
               L_VF(theta) = MSE( V(s_t), V_target_t )
               
        4. ENTROPY LOSS (Exploration Regularization):
           Measures the randomness/uncertainty of the policy's action distribution.
           Adding negative entropy encourages the policy to stay random and explore,
           preventing it from collapsing to a single deterministic action too early:
               L_ENT(theta) = -Entropy(pi)
               
        5. TOTAL LOSS FORMULATION:
           Combined objective optimized via gradient descent:
               L_TOTAL = L_CLIP + c1 * L_VF + c2 * L_ENT (where c1=0.5, c2=0.01)
        ========================================================================
        """
        # Convert lists of transition tensors to stacked single tensors
        b_states = torch.stack(trajectory_buffer["states"])
        b_actions = torch.stack(trajectory_buffer["actions"])
        b_log_probs = torch.stack(trajectory_buffer["log_probs"]).detach()
        b_rewards = torch.stack(trajectory_buffer["rewards"])
        b_state_values = torch.stack(trajectory_buffer["values"])
        b_next_states = torch.stack(trajectory_buffer["next_states"])
        
        # Determine finished masks (dones) - defaults to all False in V2X continuous serving
        if "dones" in trajectory_buffer and len(trajectory_buffer["dones"]) > 0:
            b_dones = torch.stack(trajectory_buffer["dones"])
        else:
            b_dones = torch.zeros(len(b_rewards), 1, dtype=torch.float32)

        # Step 1: Compute target returns and policy advantages
        with torch.no_grad():
            _, next_values = self.agent.model(b_next_states)
            # TD-target value bootstrap formula: V_target = r_t + gamma * V(s_{t+1}) * (1 - done)
            target_values = b_rewards + self.gamma * next_values * (1.0 - b_dones)
            
            # Advantage = Target - Predicted Value
            advantages = target_values - b_state_values
            # Normalize advantages over the batch to stabilize policy update gradients
            advantages = (advantages - advantages.mean()) / (advantages.std() + 1e-8)

        epoch_actor_loss = 0.0
        epoch_critic_loss = 0.0
        epoch_entropy_loss = 0.0
        epoch_total_loss = 0.0

        # Step 2: Run multiple inner-loop optimization epochs
        for k in range(self.ppo_epochs):
            curr_dist, curr_values = self.agent.get_action_distribution(b_states)
            
            # Log probability of actions under the current updated policy weights
            curr_log_probs = curr_dist.log_prob(b_actions).sum(dim=-1, keepdim=True)
            
            # Policy distribution entropy
            entropy = curr_dist.entropy().sum(dim=-1, keepdim=True)

            # Importance sampling ratio r = exp(log_prob_new - log_prob_old)
            ratios = torch.exp(curr_log_probs - b_log_probs.unsqueeze(-1))

            # Clipped surrogate objective calculation
            surr1 = ratios * advantages
            surr2 = torch.clamp(ratios, 1.0 - self.clip_eps, 1.0 + self.clip_eps) * advantages
            
            # Actor, Critic, and Entropy Loss components
            actor_loss = -torch.min(surr1, surr2).mean()
            critic_loss = nn.MSELoss()(curr_values, target_values)
            entropy_loss = -entropy.mean()
            
            # Total multi-objective loss optimization formula
            total_loss = actor_loss + 0.5 * critic_loss + 0.01 * entropy_loss

            # Execute backpropagation and optimizer gradient step
            self.optimizer.zero_grad()
            total_loss.backward()
            self.optimizer.step()

            # Record running training metrics
            epoch_actor_loss += actor_loss.item()
            epoch_critic_loss += critic_loss.item()
            epoch_entropy_loss += entropy_loss.item()
            epoch_total_loss += total_loss.item()

        # Compute average metrics over optimization epochs
        num_updates = self.ppo_epochs
        return {
            "actor_loss": epoch_actor_loss / num_updates,
            "critic_loss": epoch_critic_loss / num_updates,
            "entropy": -epoch_entropy_loss / num_updates,
            "total_loss": epoch_total_loss / num_updates
        }


# ==============================================================================
# Pipeline Registration
# ==============================================================================
from src.utils.registry import register_algorithm

@register_algorithm("ppo")
def build_ppo_pipeline(lr: float, port: int, mode: str, raw_data=None):
    """
    Dynamic PPO RL pipeline builder callback.
    """
    from src.models.policy_net import DefencePolicyNet
    from src.agents.v2x_agent import V2XAgent
    from src.envs.online_socket_env import V2XOnlineSocketEnv
    from src.envs.offline_dataset_env import V2XOfflineDatasetEnv
    from src.envs.translators import PpoActionTranslator
    from src.envs.rewards import PpoSurrogateReward
    from src.config import RAW_CFG
    
    cfg = RAW_CFG
    r_cfg = cfg["reward_shaping"]
    sensitivity = r_cfg["anomaly_sensitivity_threshold"]
    w_active = r_cfg["active_attack_weights"]
    w_nominal = r_cfg["nominal_traffic_weights"]
    
    translator = PpoActionTranslator()
    reward_strategy = PpoSurrogateReward(
        sensitivity_threshold=sensitivity,
        w_active=w_active,
        w_nominal=w_nominal
    )
    
    model = DefencePolicyNet()
    agent = V2XAgent(model)
    
    if mode == "online":
        env = V2XOnlineSocketEnv(port=port, action_translator=translator, reward_strategy=reward_strategy)
    else:
        env = V2XOfflineDatasetEnv(raw_data=raw_data, action_translator=translator, reward_strategy=reward_strategy)
        
    learner = PPOLearner(agent, lr=lr)
    return env, agent, learner
