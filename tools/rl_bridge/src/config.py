"""
@file config.py
@brief Configuration parser and global constants exporter for the V2X DRL agent.

This module initializes ANSI terminal colors for formatting log outputs, ingests
the centralized hyperparameters and boundaries from the YAML configuration file,
and falls back to hardcoded default configurations if the file loading fails.

NOTE FOR CODE REVIEW:
This file currently does not export the `DATA_DIR` constant, which is imported by
data_loader.py, causing an ImportError when running offline training scripts.
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
YAML_PATH = os.path.join(CONFIG_DIR, "config", "ppo_agent.yaml")

# Fallback fail-safe default maps in case YAML file loading encounters issues
_defaults = {
    "infrastructure": {
        "host": "127.0.0.1", "port": 8080, "checkpoint_dir": "checkpoints",
        "online_brain_path": "checkpoints/v2x_online_brain.pth",
        "offline_brain_path": "checkpoints/v2x_offline_rmix_e20.pth"
    },
    "v2x_bounds": {"max_packet_size": 1500.0, "max_f2_sq": 65025.0, "window_size": 64},
    "hyperparameters": {"lr_online": 0.0003, "lr_offline": 0.001, "batch_size": 32, "clip_eps": 0.2, "gamma": 0.99},
    "reward_shaping": {
        "anomaly_sensitivity_threshold": 0.05,
        "active_attack_weights": {"penalty_scale": 0.2, "sq_thresh_scale": 0.1, "budget_violation_scale": 5.0},
        "nominal_traffic_weights": {"recovery_scale": 10.0, "sq_overhead_scale": 0.1}
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
CHECKPOINT_DIR = cfg["infrastructure"]["checkpoint_dir"]
ONLINE_BRAIN_PATH = cfg["infrastructure"]["online_brain_path"]
OFFLINE_BRAIN_PATH = cfg["infrastructure"]["offline_brain_path"]

MAX_PACKET_SIZE = cfg["v2x_bounds"]["max_packet_size"]
MAX_F2_SQ = cfg["v2x_bounds"]["max_f2_sq"]
WINDOW_SIZE = cfg["v2x_bounds"]["window_size"]

# Expose the raw configuration matrix dictionary for semantic runtime deep-reads
RAW_CFG = cfg

# Dynamically locate the outputs/rl_env directory from workspace root
WORKSPACE_ROOT = os.path.dirname(os.path.dirname(CONFIG_DIR))
DATA_DIR = os.path.join(WORKSPACE_ROOT, "outputs", "rl_env")