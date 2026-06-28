# src/agent.py
import torch
from src.config import MAX_PACKET_SIZE, MAX_F2_SQ

class V2XAgent:
    """
    Encapsulates the action mapping and reward shaping logic for the DRL Agent.
    """
    def __init__(self, model):
        self.model = model

    def evaluate_window(self, window_slice):
        """
        Processes a raw dataframe window slice, extracts scaled states,
        executes forward pass, and shapes rewards/targets.
        """
        # Feature Extraction & Scaling Engineering
        avg_size = window_slice['packet_size'].mean() / MAX_PACKET_SIZE
        avg_sq = window_slice['max_sum_sq'].mean() / MAX_F2_SQ
        anomaly_rate = window_slice['is_anomalous'].mean()       
        
        state_tensor = torch.tensor([avg_size, avg_sq, anomaly_rate], dtype=torch.float32)
        
        # Execute forward pass
        action = self.model(state_tensor)
        
        # Linearly map bounded [0, 1] tensor space to operational C++ FSM parameter domains
        pred_recovery = action[0].item() * 0.5
        pred_penalty  = action[1].item() * 100.0
        pred_sq_thresh = 400 + (action[2].item() * 400)
        
        # Multi-Objective Reward Shaping Loop
        if anomaly_rate > 0.05:
            reward = (pred_penalty * 0.1) + (600.0 - pred_sq_thresh) * 0.1
        else:
            reward = (pred_recovery * 10.0) + (pred_sq_thresh - 600.0) * 0.1
            
        # Experience-driven policy gradient steering logic (Target Action generation)
        target_action = torch.zeros(3, dtype=torch.float32)
        if anomaly_rate > 0.05:
            target_action[0] = 0.1  # Low recovery rate
            target_action[1] = 0.9  # High penalty multiplier
            target_action[2] = 0.2  # Low SQ threshold (Highly sensitive)
        else:
            target_action[0] = 0.9  # High recovery rate
            target_action[1] = 0.1  # Low penalty multiplier
            target_action[2] = 0.6  # High SQ threshold
            
        return action, target_action, reward