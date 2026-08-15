"""
@file test_consistency.py
@brief pytest unit test asserting mathematical equivalence between Python translation strategies and ONNX wrappers.
"""

import os
import sys
import torch
import numpy as np
import pytest
import struct

# Adjust sys.path to find src modules relative to Python root tools/rl_bridge
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from src.envs.translators import DqnActionTranslator
from src.models.dqn_net import DQNNet
from scripts.export_onnx import DQNDeploymentWrapper
from scripts.export_onnx import DiscretePPODeploymentWrapper
from src.models.discrete_ppo_net import DiscretePPOActorCritic
from src.config import RAW_CFG
from src.envs.rewards import DqnSamplingReward
from src.utils.network_io import NetworkIOHelper

def cpp_scale(onnx_output):
    """
    Simulates C++ FSM parameter scaling in qos-harness/src/rl_bridge.cpp.
    """
    recovery = onnx_output[0] * 0.5
    penalty = onnx_output[1] * 100.0
    sq_threshold = int(400 + onnx_output[2] * 400)
    base_sampling_rate = onnx_output[3]
    return [recovery, penalty, sq_threshold, base_sampling_rate]

@pytest.fixture
def dqn_setup():
    """
    pytest fixture supplying initialized dqn network, translator, and deployment wrapper.
    """
    state_dim = 28
    action_dim = 5
    hidden_dim = 64
    action_map = RAW_CFG.get("dqn", {}).get("action_map", [-0.20, -0.10, 0.0, 0.10, 0.20])
    
    dqn_net = DQNNet(state_dim=state_dim, action_dim=action_dim, hidden_dim=hidden_dim)
    dqn_net.eval()
    
    wrapper = DQNDeploymentWrapper(dqn_net=dqn_net, action_map=action_map)
    wrapper.eval()
    
    translator = DqnActionTranslator(action_map=action_map)
    return dqn_net, wrapper, translator, action_map

def test_dqn_translation_consistency(dqn_setup):
    """
    Asserts that Python DqnActionTranslator outputs match the C++-scaled ONNX wrapper outputs.
    """
    dqn_net, wrapper, translator, action_map = dqn_setup
    
    np.random.seed(42)
    torch.manual_seed(42)
    
    num_samples = 100
    state_dim = 28
    test_states = []
    for _ in range(num_samples):
        state = np.random.uniform(0.0, 1.0, size=state_dim).tolist()
        sampling_rate = np.random.uniform(0.05, 0.8)
        state[-7] = sampling_rate
        test_states.append(state)
        
    test_tensor = torch.tensor(test_states, dtype=torch.float32)
    
    with torch.no_grad():
        q_values = dqn_net(test_tensor)
        wrapper_outputs = wrapper(test_tensor)
        
    for i in range(num_samples):
        state = test_states[i]
        curr_rate = state[-7]
        
        # A. Python pipeline path
        q_vals = q_values[i]
        best_action = q_vals.argmax().item()
        py_output = translator.translate(best_action, curr_rate)
        
        # B. C++ pipeline path (ONNX output + scaling)
        onnx_out = wrapper_outputs[i].tolist()
        cpp_output = cpp_scale(onnx_out)
        
        # Assert element-wise equality within tolerance
        for val_py, val_cpp in zip(py_output, cpp_output):
            assert abs(val_py - val_cpp) < 1e-4, (
                f"Skew detected at sample {i}! "
                f"State: {state}, chosen action index: {best_action}. "
                f"Python: {py_output}, ONNX C++: {cpp_output}"
            )


def test_discrete_ppo_wrapper_uses_expected_delta():
    """Deployment must preserve the categorical policy's mean action."""
    action_map = RAW_CFG["dqn"]["action_map"]
    model = DiscretePPOActorCritic(state_dim=30, action_dim=5, hidden_dim=128)

    # Make logits state-independent with Hold as argmax, while the combined
    # negative-action mass still produces a negative expected delta.
    with torch.no_grad():
        for parameter in model.parameters():
            parameter.zero_()
        model.actor.bias.copy_(torch.log(torch.tensor([0.38, 0.12, 0.49, 0.005, 0.005])))

    wrapper = DiscretePPODeploymentWrapper(model, action_map).eval()
    observation = torch.zeros((1, 30), dtype=torch.float32)
    observation[0, -3] = 1.0

    with torch.no_grad():
        output = wrapper(observation)[0]

    expected_delta = sum(probability * delta for probability, delta in zip(
        [0.38, 0.12, 0.49, 0.005, 0.005], action_map
    ))
    assert abs(output[3].item() - (1.0 + expected_delta)) < 1e-6
    assert output[3].item() < 1.0  # Argmax Hold would incorrectly remain at 100%.


def test_cmdp_telemetry_contract_and_actual_inspection_rate():
    payload = struct.pack(
        "<IIIIIQQfffII",
        2, 87, 1, 10, 25, 65025, 1234,
        0.50, 0.20, 55.0, 1, 400,
    )
    metrics = NetworkIOHelper.parse_telemetry(payload)
    assert metrics is not None
    assert metrics["base_sampling_rate"] == pytest.approx(0.20)
    assert metrics["effective_sampling_rate"] == pytest.approx(0.50)
    assert metrics["actual_inspection_rate"] == pytest.approx(0.25)
    assert metrics["avg_budget"] == pytest.approx(0.55)
    assert metrics["fsm_state"] == 1
    assert metrics["clean_streak"] == 400


def test_dqn_reward_uses_rolling_fnr_and_measured_work():
    reward = DqnSamplingReward(
        lambda_penalty=20.0,
        leakage_target=0.20,
        overhead_scale=1.0,
        security_horizon_windows=2,
    )
    first = reward.compute(
        {"tp_count": 0, "fn_count": 1, "base_sampling_rate": 0.10,
         "actual_inspection_rate": 0.10}, []
    )
    second = reward.compute(
        {"tp_count": 3, "fn_count": 0, "base_sampling_rate": 0.20,
         "actual_inspection_rate": 0.50}, []
    )
    assert first == pytest.approx(-16.11)
    assert reward.last_rolling_leakage_rate == pytest.approx(0.25)
    assert second == pytest.approx(-1.25)


def test_dqn_lambda_requires_attack_evidence():
    reward = DqnSamplingReward(lambda_penalty=20.0, lambda_lr=0.5, leakage_target=0.2)
    assert reward.update_lambda(0.0, malware_count=0) == pytest.approx(20.0)
    assert reward.update_lambda(0.0, malware_count=10) == pytest.approx(19.9)
    reward.lambda_penalty = 30.0
    assert reward.update_lambda(1.0, malware_count=10) == pytest.approx(30.0)
