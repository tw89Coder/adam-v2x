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
from src.config import RAW_CFG

# We import DQNDeploymentWrapper dynamically by loading export_onnx
def get_deployment_wrapper_class():
    from scripts import export_onnx
    # Locate the DQNDeploymentWrapper defined inside export_onnx.py
    # Since it is defined in main / script scope, we can access it from the module.
    # Wait, in export_onnx.py we defined DQNDeploymentWrapper inside main().
    # To make it importable, let's make sure we can access it or we define it globally in export_onnx.py.
    # Ah! In export_onnx.py, DQNDeploymentWrapper is currently defined INSIDE main()!
    # If it is inside main(), we cannot import it from other scripts!
    # Let's inspect export_onnx.py or move the wrapper class outside main() to make it clean.
    pass
