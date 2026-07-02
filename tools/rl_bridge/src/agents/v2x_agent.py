"""
@file v2x_agent.py
@brief Agent wrapper managing PyTorch model inference, stochastic action sampling, and the Action Adapter.

This module houses the V2XAgent. It coordinates neural network queries and maps
continuous action outputs to the physical parameter expectations of the C++ simulation.
"""

from typing import Tuple, List, Dict, Any
import torch
from torch.distributions import Normal

from src.config import RAW_CFG
from src.agents.base_agent import BaseV2XAgent

class V2XAgent(BaseV2XAgent):
    """
    Stochastic Policy Agent executing dynamic parameter scaling and Action Adaptation.
    """
    def __init__(self, model: torch.nn.Module):
        """
        @param model torch.nn.Module The PyTorch policy network model.
        """
        self.model = model
        
        cfg = RAW_CFG["action_space"]
        self.wire_params = cfg["wire_protocol_parameters"]
        self.rl_controlled = cfg["rl_controlled_actions"]
        self.static_defaults = cfg["static_defaults"]
        self.scaling_bounds = cfg["scaling_bounds"]
        self.safety_cfg = RAW_CFG.get("safety_boundaries", {})
        
        # Verify that all RL-controlled variables exist in the wire protocol definition
        for act_name in self.rl_controlled:
            if act_name not in self.wire_params:
                raise ValueError(
                    f"Configuration Error: RL-controlled action '{act_name}' "
                    f"is not defined in wire_protocol_parameters: {self.wire_params}"
                )

    def enforce_safety_heuristics(self, serialized_actions: list) -> list:
        """
        Applies safety boundaries guards on simulation actions.
        """
        if not self.safety_cfg.get("enabled", True):
            return serialized_actions
            
        recovery = serialized_actions[0]
        penalty = serialized_actions[1]
        sq_thresh = serialized_actions[2]
        base_samp = serialized_actions[3]
        
        max_sq = self.safety_cfg.get("max_sq_threshold", 650)
        min_pen = self.safety_cfg.get("min_penalty_multiplier", 20.0)
        max_rec = self.safety_cfg.get("max_recovery_rate", 0.10)
        min_samp = self.safety_cfg.get("min_base_sampling_rate", 0.05)

        if sq_thresh > max_sq:
            sq_thresh = max_sq
        if penalty < min_pen:
            penalty = min_pen
        if recovery > max_rec:
            recovery = max_rec
        if base_samp < min_samp:
            base_samp = min_samp
            
        return [recovery, penalty, sq_thresh, base_samp]

    def get_action_distribution(self, state_tensor: torch.Tensor) -> Tuple[Normal, torch.Tensor]:
        """
        Queries policy network to parameterize the Gaussian policy action distribution.
        
        @return Tuple containing:
            - Normal distribution representing the continuous policy.
            - State value tensor estimated by the Critic head.
        """
        action_mean, state_value = self.model(state_tensor)
        action_std = torch.exp(self.model.log_std)
        return Normal(action_mean, action_std), state_value

    def map_actions_to_environment(self, action_values: torch.Tensor) -> Tuple[list, list]:
        """
        ========================================================================
        ACTION ADAPTER DEVELOPER GUIDE & WALKTHROUGH
        ========================================================================
        This Action Adapter maps raw network outputs (clamped [0.0, 1.0]) to the 
        physical parameters expected by the C++ simulation.
        
        HOW TO ADD OR MODIFY A PARAMETER:
        ------------------------------------------------------------------------
        1. Open config/ppo_agent.yaml
        2. To keep a parameter static:
           - Define its name in `wire_protocol_parameters`.
           - Set its default value in `static_defaults`.
           - Do NOT add it to `rl_controlled_actions`.
        3. To put a parameter under Reinforcement Learning control:
           - Move/Add its name to the `rl_controlled_actions` list.
           - Define its physical scale bounds [min, max] under `scaling_bounds`.
           - Remove it from `static_defaults`.
        
        Zero Python code changes are required! The network size (action_dim) 
        and scaling mappings will adapt automatically.
        ========================================================================
        """
        # Convert model outputs to a flat list
        raw_vals = action_values.flatten().tolist()
        
        # Clamp raw network output to [0.0, 1.0] representing normal boundaries
        clamped_vals = [max(0.0, min(1.0, val)) for val in raw_vals]
        
        # Map each active RL action to its physical range
        mapped_rl_actions = {}
        for idx, param_name in enumerate(self.rl_controlled):
            bounds = self.scaling_bounds.get(param_name, {"min": 0.0, "max": 1.0})
            scaled_val = bounds["min"] + (clamped_vals[idx] * (bounds["max"] - bounds["min"]))
            mapped_rl_actions[param_name] = scaled_val
            
        # Build the final ordered list sent over the network
        raw_output_sequence = []
        for param_name in self.wire_params:
            if param_name in self.rl_controlled:
                # Value comes from the RL model output
                raw_output_sequence.append(mapped_rl_actions[param_name])
            else:
                # Value comes from the static defaults in configuration
                default_val = self.static_defaults.get(param_name, 0.0)
                raw_output_sequence.append(default_val)
                
        # Enforce safety boundaries to generate the final safe output sequence
        safe_output_sequence = self.enforce_safety_heuristics(raw_output_sequence)
                
        # Return lists of values representing actions before and after safety boundaries
        return raw_output_sequence, safe_output_sequence

    def act(self, state_tensor: torch.Tensor) -> Tuple[torch.Tensor, Tuple[list, list], torch.Tensor, torch.Tensor]:
        """
        Executes a stochastic forward pass to sample action parameters.
        
        @return Tuple containing:
            - sampled_action (torch.Tensor) Raw policy output tensor before clamp/scale.
            - adapted_actions (Tuple[list, list]) Raw & safe parameter lists in wire-protocol order.
            - log_prob (torch.Tensor) Log probability of the sampled action.
            - state_value (torch.Tensor) Estimated Critic state value.
        """
        dist, state_value = self.get_action_distribution(state_tensor)
        action = dist.sample()
        log_prob = dist.log_prob(action).sum(dim=-1)
        
        # Adapt action dimensions dynamically
        adapted_actions = self.map_actions_to_environment(action)
        
        return action, adapted_actions, log_prob, state_value