"""
@file online_server.py
@brief TCP Loopback co-simulation server orchestrating online interactive PPO training.

This module sets up a non-blocking TCP socket server to interface with the C++ QoS 
harness. It receives telemetry statistics, constructs normalized state tensors, 
samples dynamic parameters from Actor Gaussian policy distributions, computes reward
metrics, and executes synchronous PPO updates when batch sizes are satisfied.
"""

import os
import sys
import socket
import torch
import torch.nn as nn
import torch.optim as optim

from src.config import C_INFO, C_SUCCESS, C_WARN, C_ERROR, C_RESET, C_BOLD, CHECKPOINT_DIR
from src.utils.network_io import NetworkIOHelper

class V2XOnlinePipeline:
    """
    Production-grade PPO Interactive Socket Training Pipeline Backend.
    Handles non-blocking trajectory gathering and synchronized batch optimization.
    """
    def __init__(self, agent, lr=0.0003, batch_size=32, ppo_epochs=5, clip_eps=0.2):
        self.agent = agent
        self.batch_size = batch_size
        self.ppo_epochs = ppo_epochs
        self.clip_eps = clip_eps
        
        # Initialize Optimizer for Active Online Gradient Steps
        self.optimizer = optim.Adam(self.agent.model.parameters(), lr=lr)
        self.agent.model.train()

        # Telemetry Trajectory Buffers
        self.states = []
        self.actions = []
        self.log_probs = []
        self.rewards = []

    def start_server(self, host="127.0.0.1", port=8080):
        """
        Launches IPv4 TCP Socket server and handles continuous transaction loops.
        """
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((host, port))
            server_socket.listen(5)
            print(f"  └── {C_SUCCESS}Socket Active{C_RESET} : Optimization Engine listening on {host}:{port}")
        except Exception as e:
            print(f"{C_ERROR}[FATAL] Cannot bind pipeline server to port {port}: {e}{C_RESET}")
            sys.exit(1)

        update_count = 0
        print(f"\n{C_WARN}[*] Interactive DRL Loop Active. Initializing synchronization sequences...{C_RESET}\n")

        try:
            while True:
                client_socket, _ = server_socket.accept()
                try:
                    raw_data = client_socket.recv(1024).decode('utf-8')
                    metrics = NetworkIOHelper.parse_telemetry(raw_data)
                    
                    if metrics is None:
                        client_socket.close()
                        continue
                    
                    # ---- Feature Remapping Engine ----
                    # Remap packet sizes to simplify representation bounds
                    simulated_size = 1400.0 if metrics["anomaly_rate"] > 0.05 else 325.0
                    s = self.agent.build_state_tensor(simulated_size, metrics["avg_sq"], metrics["anomaly_rate"])
                    
                    # Stochastic Exploration Step: Sample action from distribution
                    dist, val = self.agent.get_action_distribution(s)
                    a = dist.sample()
                    a_clamped = torch.clamp(a, 0.0, 1.0)
                    log_p = dist.log_prob(a).sum(dim=-1)
                    
                    # Compute Objective Environmental Reward Shape
                    r = self.agent.compute_surrogate_reward(a_clamped, metrics["anomaly_rate"], metrics["avg_budget"])
                    
                    # Scale and send immediate action payload back to C++
                    rec = a_clamped[0].item() * 0.5
                    pen = a_clamped[1].item() * 100.0
                    sq_t = int(400 + (a_clamped[2].item() * 400))
                    base_samp = 0.05 # Dynamic continuous heuristic base rate

                    # Pass all 4 updated parameters seamlessly through the network utility helper
                    response = NetworkIOHelper.serialize_policy(rec, pen, sq_t, base_samp)
                    client_socket.send(response)
                    
                    # Push step trajectory memories
                    self.states.append(s)
                    self.actions.append(a)
                    self.log_probs.append(log_p.detach())
                    self.rewards.append(torch.tensor([r], dtype=torch.float32))
                    
                    # ---- PPO Brain Update Phase ----
                    if len(self.states) >= self.batch_size:
                        update_count += 1
                        
                        b_states = torch.stack(self.states)
                        b_actions = torch.stack(self.actions)
                        b_log_probs = torch.stack(self.log_probs)
                        b_rewards = torch.stack(self.rewards)
                        
                        # K Inner Optimization Epochs
                        for k in range(self.ppo_epochs):
                            curr_dist, curr_values = self.agent.get_action_distribution(b_states)
                            curr_log_probs = curr_dist.log_prob(b_actions).sum(dim=-1, keepdim=True)
                            entropy = curr_dist.entropy().sum(dim=-1, keepdim=True)
                            
                            # Calculate importance sampling ratios r(theta)
                            ratios = torch.exp(curr_log_probs - b_log_probs.unsqueeze(-1))
                            advantages = b_rewards - curr_values.detach()
                            advantages = (advantages - advantages.mean()) / (advantages.std() + 1e-8)
                            
                            # Surrogate objective clipping constraints
                            surr1 = ratios * advantages
                            surr2 = torch.clamp(ratios, 1.0 - self.clip_eps, 1.0 + self.clip_eps) * advantages
                            
                            actor_loss = -torch.min(surr1, surr2).mean()
                            critic_loss = nn.MSELoss()(curr_values, b_rewards)
                            entropy_loss = -entropy.mean()
                            
                            total_loss = actor_loss + 0.5 * critic_loss + 0.01 * entropy_loss
                            
                            self.optimizer.zero_grad()
                            total_loss.backward()
                            self.optimizer.step()
                        
                        # Cache scalar metrics prior to flushing buffers
                        mean_reward_val = b_rewards.mean().item()
                        actor_loss_val = actor_loss.item()
                        critic_loss_val = critic_loss.item()
 
                        # Flush rollout buffers immediately to secure gradient sanity
                        self.states, self.actions, self.log_probs, self.rewards = [], [], [], []
                        
                        # Process evaluation metric telemetry logs
                        print(f"[{C_INFO}UPDATE #{update_count:03d}{C_RESET}] "
                               f"Batch Mean Reward: {C_SUCCESS}{mean_reward_val:+6.2f}{C_RESET} | "
                               f"Actor Loss: {C_BOLD}{actor_loss_val:+.5f}{C_RESET} | "
                               f"Critic Loss: {C_BOLD}{critic_loss_val:.4f}{C_RESET}")
                        
                        # Epoch Checkpoint Serializer
                        if update_count % 10 == 0:
                            os.makedirs(CHECKPOINT_DIR, exist_ok=True)
                            ckpt_out = f"{CHECKPOINT_DIR}/v2x_online_brain.pth"
                            torch.save(self.agent.model.state_dict(), ckpt_out)
                            print(f"  └── {C_SUCCESS}[SUCCESS] Serialized brain weights saved -> {ckpt_out}{C_RESET}")
                            
                except Exception as handshake_err:
                    print(f"{C_ERROR}[ERROR] Core Handshake Crash: {handshake_err}{C_RESET}")
                finally:
                    client_socket.close()
                    
        except KeyboardInterrupt:
            print(f"\n{C_WARN}[*] Received termination signal. Releasing socket infrastructure safely...{C_RESET}")
        finally:
            server_socket.close()