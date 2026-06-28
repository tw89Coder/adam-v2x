# src/config.py
import os

# Terminal Signaling ANSI Color Codes
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_INFO = "\033[1;36m"
C_SUCCESS = "\033[1;32m"
C_WARN = "\033[1;33m"
C_ERROR = "\033[1;41;37m"
C_WHITE = "\033[1;37m"

# Hyperparameters & Constants
WINDOW_SIZE = 1000
DATA_DIR = "../../outputs/rl_env"
CHECKPOINT_DIR = "checkpoints"

# V2X Operational Data Plane Boundaries (Normalization Factors)
MAX_PACKET_SIZE = 1500.0
MAX_F2_SQ = 1000.0