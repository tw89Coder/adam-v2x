# src/config.py
import os
import yaml

# Initialize standard terminal signaling ANSI color codes
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_WHITE = "\033[1;37m"
C_INFO = "\033[1;36m"
C_SUCCESS = "\033[1;32m"
C_WARN = "\033[1;33m"
C_ERROR = "\033[1;41;37m"

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