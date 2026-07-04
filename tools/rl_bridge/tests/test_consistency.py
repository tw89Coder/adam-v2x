"""
@file test_consistency.py
@brief Unit test validating consistency between Python DRL strategies and PyTorch ONNX deployment wrappers.
Guarantees zero Training-Serving Skew.
"""

import os
import sys
import torch
import numpy as np

# Ensure absolute paths resolve relative to Python root tools/rl_bridge
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from src.envs.translators import DqnActionTranslator
from src.models.dqn_net import DQNNet
from scripts.export_onnx import DQNDeploymentWrapper
from src.config import RAW_CFG

def cpp_scale(onnx_output):
    """
    Simulates C++ FSM parameter scaling in qos-harness/src/rl_bridge.cpp.
    """
    recovery = onnx_output[0] * 0.5
    penalty = onnx_output[1] * 100.0
    sq_threshold = int(400 + onnx_output[2] * 400)
    base_sampling_rate = onnx_output[3]
    return [recovery, penalty, sq_threshold, base_sampling_rate]

def test_dqn_consistency():
    print("[TEST] Running DQN Action Translator vs. ONNX Wrapper consistency check...")
    
    # 1. Setup parameters
    state_dim = 3
    action_dim = 5
    hidden_dim = 64
    action_map = RAW_CFG.get("dqn", {}).get("action_map", [-0.10, -0.05, 0.0, 0.05, 0.10])
    
    # 2. Instantiate networks
    dqn_net = DQNNet(state_dim=state_dim, action_dim=action_dim, hidden_dim=hidden_dim)
    dqn_net.eval()
    
    wrapper = DQNDeploymentWrapper(dqn_net=dqn_net, action_map=action_map)
    wrapper.eval()
    
    translator = DqnActionTranslator(action_map=action_map)
    
    # 3. Generate random observations
    np.random.seed(42)
    torch.manual_seed(42)
    
    num_samples = 100
    test_states = []
    for _ in range(num_samples):
        # Sampling rate in range [0.05, 1.0]
        sampling_rate = np.random.uniform(0.05, 1.0)
        avg_sq = np.random.uniform(0.0, 1.0)
        anomaly_rate = np.random.uniform(0.0, 1.0)
        test_states.append([sampling_rate, avg_sq, anomaly_rate])
        
    test_tensor = torch.tensor(test_states, dtype=torch.float32)
    
    # 4. Run predictions
    with torch.no_grad():
        q_values = dqn_net(test_tensor)
        wrapper_outputs = wrapper(test_tensor)
        
    # 5. Assert consistency
    for i in range(num_samples):
        state = test_states[i]
        curr_rate = state[0]
        
        # A. Python pipeline path
        q_vals = q_values[i]
        best_action = q_vals.argmax().item()
        py_output = translator.translate(best_action, curr_rate)
        
        # B. C++ pipeline path (ONNX output + scaling)
        onnx_out = wrapper_outputs[i].tolist()
        cpp_output = cpp_scale(onnx_out)
        
        # Assert equal values
        for val_py, val_cpp in zip(py_output, cpp_output):
            assert abs(val_py - val_cpp) < 1e-4, (
                f"Training-Serving Skew detected at sample {i}!\n"
                f"State: {state}\n"
                f"Action Map: {action_map}\n"
                f"Chosen discrete index: {best_action}\n"
                f"Python output: {py_output}\n"
                f"ONNX C++ scaled output: {cpp_output}"
            )
            
    print(f"[SUCCESS] Checked {num_samples} samples. Python and ONNX Wrapper are 100% consistent!")

if __name__ == "__main__":
    test_dqn_consistency()
