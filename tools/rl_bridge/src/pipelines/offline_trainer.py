# src/pipelines/offline_trainer.py
import torch
import torch.nn as nn
import torch.optim as optim
from src.config import WINDOW_SIZE, C_WHITE, C_RESET, C_INFO, C_BOLD, C_SUCCESS

class V2XOfflinePipeline:
    """
    Industrial Offline Batch PPO Optimization Engine.
    Fixes the 'Actor Loss = 0' bug by executing proper multi-epoch policy importance sampling.
    """
    def __init__(self, agent, lr=0.001, clip_eps=0.2, ppo_epochs=10):
        self.agent = agent
        self.clip_eps = clip_eps
        self.ppo_epochs = ppo_epochs
        
        # Instantiate localized optimizer targeting policy parameters
        self.optimizer = optim.Adam(self.agent.model.parameters(), lr=lr)

    def train_episodes(self, raw_data, total_epochs):
        total_packets = len(raw_data)
        num_windows = total_packets // WINDOW_SIZE

        for epoch in range(total_epochs):
            epoch_total_reward = 0.0
            
            # Rollout storage buffers for parallelized trajectory parsing
            states, actions, log_probs, rewards, state_values, next_states = [], [], [], [], [], []
            
            # Phase 1: Batch Trajectory Rollout Accumulation
            for w in range(num_windows - 1):
                window_slice = raw_data.iloc[w * WINDOW_SIZE : (w + 1) * WINDOW_SIZE]
                next_window_slice = raw_data.iloc[(w + 1) * WINDOW_SIZE : (w + 2) * WINDOW_SIZE]
                
                # Call single source of truth state estimators from the agent helper
                s = self.agent.extract_state_from_offline_df(window_slice)
                s_next = self.agent.extract_state_from_offline_df(next_window_slice)
                
                dist, val = self.agent.get_action_distribution(s)
                
                # Stochastic sampling during batch tracing
                a = dist.sample()
                a_clamped = torch.clamp(a, 0.0, 1.0)
                log_p = dist.log_prob(a).sum(dim=-1)
                
                anomaly_rate = s[2].item()
                current_budget = window_slice['current_budget'].mean()
                r = self.agent.compute_surrogate_reward(a_clamped, anomaly_rate, current_budget)
                
                states.append(s)
                actions.append(a)
                log_probs.append(log_p)
                state_values.append(val)
                rewards.append(torch.tensor([r], dtype=torch.float32))
                next_states.append(s_next)
                epoch_total_reward += r

            # Stack collected elements into uniform continuous tensor arrays
            b_states = torch.stack(states)
            b_actions = torch.stack(actions)
            b_log_probs = torch.stack(log_probs).detach()
            b_rewards = torch.stack(rewards)
            b_state_values = torch.stack(state_values)
            b_next_states = torch.stack(next_states)

            # Bootstrap values across time horizons (Gamma = 0.99)
            with torch.no_grad():
                _, next_values = self.agent.model(b_next_states)
                target_values = b_rewards + 0.99 * next_values
                
                # Compute historical policy advantages outside the mini-batch gradient step loop
                advantages = target_values - b_state_values
                advantages = (advantages - advantages.mean()) / (advantages.std() + 1e-8)

            # Phase 2: K-Epoch Inner Optimization Loop (True PPO Convergence Guard)
            for k in range(self.ppo_epochs):
                curr_dist, curr_values = self.agent.get_action_distribution(b_states)
                curr_log_probs = curr_dist.log_prob(b_actions).sum(dim=-1, keepdim=True)
                entropy = curr_dist.entropy().sum(dim=-1, keepdim=True)

                # Importance sampling policy ratio updates (ratios diverge from 1.0 as k increases)
                ratios = torch.exp(curr_log_probs - b_log_probs.unsqueeze(-1))

                # Clip surrogate objective constraints
                surr1 = ratios * advantages
                surr2 = torch.clamp(ratios, 1.0 - self.clip_eps, 1.0 + self.clip_eps) * advantages
                
                actor_loss = -torch.min(surr1, surr2).mean()
                critic_loss = nn.MSELoss()(curr_values, target_values)
                entropy_loss = -entropy.mean()
                
                # Unified loss mapping
                total_loss = actor_loss + 0.5 * critic_loss + 0.01 * entropy_loss

                self.optimizer.zero_grad()
                total_loss.backward()
                self.optimizer.step()

            # Display real metrics representing the final optimization boundary step of the epoch
            print(f"  {C_WHITE}──{C_RESET} [ {C_INFO}Epoch {epoch+1:02d}/{total_epochs:02d}{C_RESET} ] "
                  f"Actor Loss: {C_BOLD}{actor_loss.item():+.5f}{C_RESET} | "
                  f"Critic Loss: {C_BOLD}{critic_loss.item():.5f}{C_RESET} | "
                  f"Mean Reward: {C_SUCCESS}{epoch_total_reward / num_windows:+.2f}{C_RESET}")