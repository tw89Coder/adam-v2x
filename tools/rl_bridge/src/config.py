"""
@file config.py
@brief Configuration parser and global constants exporter for the V2X DRL agent.

This module initializes ANSI terminal colors for formatting log outputs, ingests
the centralized hyperparameters and boundaries from the YAML configuration file,
and falls back to hardcoded default configurations if the file loading fails.
"""

import os
import yaml

# Initialize standard terminal signaling ANSI color codes for formatted logging
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_WHITE = "\033[1;37m"
C_INFO = "\033[1;36m"
C_SUCCESS = "\033[1;32m"
C_WARN = "\033[1;33m"
C_ERROR = "\033[1;31m"

# Locate the external YAML file layout relative to project infrastructure
CONFIG_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKSPACE_ROOT = os.path.dirname(os.path.dirname(CONFIG_DIR))
YAML_PATH = os.path.join(CONFIG_DIR, "config", "agent.yaml")

# Fallback fail-safe default maps in case YAML file loading encounters issues
_defaults = {
    "algorithm": "dqn",
    "state_representation": {
        "frame_stack": 1
    },
    "infrastructure": {
        "host": "127.0.0.1", "port": 8080, "checkpoint_dir": "checkpoints",
        "online_brain_path": "checkpoints/v2x_online_brain.pth",
        "offline_brain_path": "checkpoints/v2x_offline_rmix_e20.pth"
    },
    "v2x_bounds": {"max_packet_size": 1500.0, "max_f2_sq": 65025.0, "window_size": 64},
    "models": {
        "hidden_layers": [64, 64]
    },
    "action_space": {
        "wire_protocol_parameters": ["recovery_rate", "penalty_multiplier", "sq_threshold", "base_sampling_rate"],
        "rl_controlled_actions": ["recovery_rate", "penalty_multiplier"],
        "static_defaults": {"sq_threshold": 650.0, "base_sampling_rate": 0.05},
        "scaling_bounds": {
            "recovery_rate": {"min": 0.0, "max": 0.5},
            "penalty_multiplier": {"min": 0.0, "max": 100.0},
            "sq_threshold": {"min": 400.0, "max": 800.0},
            "base_sampling_rate": {"min": 0.01, "max": 0.20}
        }
    },
    "hyperparameters": {
        "input_dim": 3, "lr_online": 0.0003, "lr_offline": 0.001, "batch_size": 32,
        "ppo_epochs_online": 5, "ppo_epochs_offline": 10, "clip_eps": 0.2, "gamma": 0.99
    },
    "reward_shaping": {
        "anomaly_sensitivity_threshold": 0.005,
        "active_attack_weights": {"penalty_scale": 0.5, "sq_thresh_scale": 0.2, "budget_violation_scale": 10.0},
        "nominal_traffic_weights": {"recovery_scale": 10.0, "sq_overhead_scale": 0.1, "overhead_penalty_scale": 8.0}
    },
    "safety_boundaries": {
        "enabled": True, "max_sq_threshold": 650, "min_penalty_multiplier": 20.0,
        "max_recovery_rate": 0.10, "min_base_sampling_rate": 0.05
    },
    "dqn": {
        "action_map": [-0.10, -0.05, 0.0, 0.05, 0.10],
        "capacity": 10000,
        "eps_start": 1.0,
        "eps_end": 0.05,
        "eps_decay": 1000,
        "tau": 0.005,
        "hidden_dim": 64,
        "reward_shaping": {
            "lambda_penalty": 10.0,
            "lambda_lr": 0.05,
            "leakage_target": 0.01,
            "overhead_scale": 2.0
        }
    }
}

# Dynamic Ingestion Process
if os.path.exists(YAML_PATH):
    try:
        with open(YAML_PATH, "r") as f:
            cfg = yaml.safe_load(f) or _defaults
    except Exception:
        cfg = _defaults
else:
    cfg = _defaults

# Export flat global constants to prevent breaking current downstream scripts
HOST = cfg["infrastructure"]["host"]
PORT = cfg["infrastructure"]["port"]
CHECKPOINT_DIR = os.path.join(WORKSPACE_ROOT, cfg["infrastructure"]["checkpoint_dir"])

# Append algorithm suffix to prevent PPO/DQN checkpoint overwrites
ALGO_SUFFIX = f"_{cfg.get('algorithm', 'dqn').lower()}"
online_base, ext = os.path.splitext(cfg["infrastructure"]["online_brain_path"])
offline_base, ext = os.path.splitext(cfg["infrastructure"]["offline_brain_path"])

ONLINE_BRAIN_PATH = os.path.join(WORKSPACE_ROOT, f"{online_base}{ALGO_SUFFIX}{ext}")
OFFLINE_BRAIN_PATH = os.path.join(WORKSPACE_ROOT, f"{offline_base}{ALGO_SUFFIX}{ext}")

MAX_PACKET_SIZE = cfg["v2x_bounds"]["max_packet_size"]
MAX_F2_SQ = cfg["v2x_bounds"]["max_f2_sq"]
WINDOW_SIZE = cfg["v2x_bounds"]["window_size"]
FRAME_STACK = cfg.get("state_representation", {}).get("frame_stack", 1)

# Expose the raw configuration matrix dictionary for semantic runtime deep-reads
RAW_CFG = cfg

# Dynamically locate the outputs/rl_env directory from workspace root
DATA_DIR = os.path.join(WORKSPACE_ROOT, "outputs", "rl_env")