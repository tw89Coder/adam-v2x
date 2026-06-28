# src/utils/data_loader.py
import os
import sys
import glob
import random
import pandas as pd
from src.config import DATA_DIR, C_ERROR, C_INFO, C_RESET, WINDOW_SIZE

def load_telemetry_data(rate_str):
    """
    Ingests single or blended telemetry datasets from disk based on the rate selector.
    Preserves structural packet order within discrete window slices to prevent evaluation bias.
    """
    if rate_str.lower() == "mix":
        pattern = os.path.join(DATA_DIR, "training_trace_*_mode3.csv")
        file_list = glob.glob(pattern)
        if not file_list:
            print(f"\n{C_ERROR}[FATAL] No telemetry trace files found matching pattern: {pattern}{C_RESET}")
            sys.exit(1)
        
        print(f"  ├── {C_INFO}Joint Training Mode:{C_RESET} Ingesting and blending {len(file_list)} trace matrices...")
        
        # Extract structurally continuous windows per trajectory file to preserve packet-level timeline
        all_windows = []
        for f in file_list:
            df = pd.read_csv(f)
            num_windows = len(df) // WINDOW_SIZE
            for w in range(num_windows):
                window_slice = df.iloc[w * WINDOW_SIZE : (w + 1) * WINDOW_SIZE]
                all_windows.append(window_slice)
        
        # Execute window-level shuffling to mitigate macro chronological bias (Catastrophic Forgetting)
        random.seed(42)
        random.shuffle(all_windows)
        
        # Concatenate structural blocks back into a single unified execution telemetry frame
        raw_data = pd.concat(all_windows, ignore_index=True)
    else:
        # Fallback path for single trajectory execution matrix profile
        try:
            rate_val = float(rate_str)
        except ValueError:
            print(f"\n{C_ERROR}[FATAL] Invalid rate format: {rate_str}. Use a number or 'mix'.{C_RESET}")
            sys.exit(1)
            
        csv_path = f"{DATA_DIR}/training_trace_{rate_val:.1f}_mode3.csv"
        if not os.path.exists(csv_path):
            print(f"\n{C_ERROR}[FATAL] Target telemetry trajectory source missing at: {csv_path}{C_RESET}")
            sys.exit(1)
        print(f"  ├── Data Pipeline    : Ingesting single telemetry data matrix...")
        raw_data = pd.read_csv(csv_path)
        
    return raw_data