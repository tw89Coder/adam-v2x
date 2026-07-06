"""
@file sac_learner.py
@brief Skeleton template for Soft Actor-Critic (SAC) algorithm integration.

This module serves as a concrete code documentation example showing how a developer 
can implement a different reinforcement learning algorithm and plug it into the framework.
"""

from typing import Dict, List, Any
import torch

from src.algorithms.base_learner import BaseLearner

class SACLearner(BaseLearner):
    """
    Template Optimizer for Soft Actor-Critic (SAC).
    ============================================================================
    DEVELOPER IMPLEMENTATION GUIDE:
    ----------------------------------------------------------------------------
    To implement SAC (or another continuous action space algorithm):
    
    1. NETWORK MODIFICATIONS:
       SAC utilizes separate actor and double-critic networks (rather than a shared torso):
       - Policy network: Outputs mean and standard deviation for actions.
       - Q-networks: Two independent state-action Q-value estimators (Q1, Q2).
       Define these under `src/models/` or construct them here.
       
    2. GRADIENT UPDATE METHOD (implemented in update()):
       - Sample trajectories from buffer.
       - Update Critic networks:
         Target Q = Reward + Gamma * (Min_Q(Next_State, Next_Action) - Alpha * Log_Prob)
         Loss Q = MSE(Q(State, Action), Target Q)
       - Update Actor network:
         Actor Loss = Alpha * Log_Prob - Q(State, Sampled_Action)
       - Update Temperature (Alpha):
         Optimize entropy tuning coefficients.
       
    3. SWAPPING THE ALGORITHM:
       - Implement the update logic below.
       - Register this learner in the `src/main.py` dynamic Factory.
       - Set `algorithm: "sac"` in `config/ppo_agent.yaml`.
    ============================================================================
    """
    def __init__(self, agent: Any = None, lr: float = 0.0003):
        self.agent = agent
        self.lr = lr
        
    def update(self, trajectory_buffer: Dict[str, List[torch.Tensor]]) -> Dict[str, float]:
        """
        Skeleton method. Developers implement the mathematical gradient steps here.
        """
        # Placeholder illustrating returns
        return {
            "actor_loss": 0.0,
            "critic_loss": 0.0,
            "entropy": 0.0,
            "total_loss": 0.0
        }


# ==============================================================================
# Pipeline Registration
# ==============================================================================
from src.utils.registry import register_algorithm

@register_algorithm("sac")
def build_sac_pipeline(lr: float, port: int, mode: str, raw_data=None, frame_stack: int = 1, **kwargs):
    """
    Dynamic SAC RL pipeline builder callback.
    """
    from src.models.policy_net import DefencePolicyNet
    from src.agents.v2x_agent import V2XAgent
    from src.envs.online_socket_env import V2XOnlineSocketEnv
    from src.envs.offline_dataset_env import V2XOfflineDatasetEnv
    from src.envs.translators import PpoActionTranslator
    from src.envs.rewards import PpoSurrogateReward
    from src.algorithms.sac_learner import SACLearner
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
    
    if mode == "online":
        env = V2XOnlineSocketEnv(port=port, action_translator=translator, reward_strategy=reward_strategy)
    else:
        env = V2XOfflineDatasetEnv(raw_data=raw_data, action_translator=translator, reward_strategy=reward_strategy)
        
    if frame_stack > 1:
        from src.envs.wrappers import FrameStackWrapper
        env = FrameStackWrapper(env, k=frame_stack)
        
    state_dim = env.state_dim if hasattr(env, "state_dim") else (len(env.active_features) if hasattr(env, "active_features") else 3)
    
    model = DefencePolicyNet(input_dim=state_dim)
    agent = V2XAgent(model)
    learner = SACLearner(agent, lr=lr)
    return env, agent, learner

