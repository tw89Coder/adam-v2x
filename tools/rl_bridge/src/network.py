# src/network.py
import torch
import torch.nn as nn

class DefencePolicyNet(nn.Module):
    """
    Multi-Layer Perceptron (MLP) Policy Network for adaptive V2X FSM parameter regulation.
    Input Space  : [Normalized_Packet_Size, Normalized_F2_SQ_Score, Anomaly_Injection_Rate]
    Output Space : [Recovery_Rate, Penalty_Multiplier, SQ_Threshold] (Bounded via Sigmoid)
    """
    def __init__(self, input_dim=3, hidden_dim=64, output_dim=3):
        super(DefencePolicyNet, self).__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.relu = nn.ReLU()
        self.fc_out = nn.Linear(hidden_dim, output_dim)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        out = self.relu(self.fc1(x))
        out = self.sigmoid(self.fc_out(out))
        return out