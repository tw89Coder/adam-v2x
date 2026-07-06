#!/usr/bin/env python3
# ==============================================================================
# Python-C++ ONNX Equivalence Validator (Sanity Check Engine)
# ==============================================================================
"""
@file verify_equivalence.py
@brief Standalone validation utility to check numeric alignment between Python and C++ ONNX inference.
"""

import os
import sys
import argparse
import subprocess
import numpy as np
import onnxruntime as ort

# High-contrast terminal color standards matching repository specifications
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_INFO = "\033[1;36m"
C_SUCCESS = "\033[1;32m"
C_WARN = "\033[1;33m"
C_ERROR = "\033[1;41;37m"

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)

    parser = argparse.ArgumentParser(description="DRL ONNX Model Equivalence Validator.")
    parser.add_argument("-o", "--onnx", type=str, default="checkpoints/v2x_agent_dqn.onnx",
                        help="Path to the exported ONNX model binary (Default: checkpoints/v2x_agent_dqn.onnx)")
    parser.add_argument("-t", "--target", type=str, choices=["patched", "unpatched"], default="patched",
                        help="Target C++ compiled simulation binary workspace (Default: patched)")
    args = parser.parse_args()

    # Resolve absolute paths
    onnx_path = args.onnx if os.path.isabs(args.onnx) else os.path.join(project_root, args.onnx)
    cpp_binary = os.path.join(project_root, f"vanetza_{args.target}", "build", "bin", "qos-harness")

    print(f"{C_INFO}[*] Initiating Equivalence Sanity Check...{C_RESET}")
    print(f"  └── ONNX Model Path: {C_BOLD}{onnx_path}{C_RESET}")
    print(f"  └── C++ Target Binary: {C_BOLD}{cpp_binary}{C_RESET}")

    # --------------------------------------------------------------------------
    # Step 1: Validate Files Presence
    # --------------------------------------------------------------------------
    if not os.path.exists(onnx_path):
        print(f"{C_ERROR}[ERROR] ONNX Model file not found at: {onnx_path}{C_RESET}")
        sys.exit(1)
    if not os.path.exists(cpp_binary):
        print(f"{C_ERROR}[ERROR] C++ target binary not found at: {cpp_binary}{C_RESET}")
        print(f"{C_WARN}[SUGGESTION] Run './manage_build.sh {args.target}' first to compile the binary.{C_RESET}")
        sys.exit(1)

    # --------------------------------------------------------------------------
    # Step 2: Run Python Side ONNX Inference
    # --------------------------------------------------------------------------
    try:
        session = ort.InferenceSession(onnx_path)
        input_name = session.get_inputs()[0].name
        input_shape = session.get_inputs()[0].shape
        input_dim = input_shape[-1]
        
        # Determine Frame Stack K dynamically
        K = input_dim // 3
        print(f"{C_INFO}[*] Python ONNX Session initialized. Input dimension: {input_dim} (K = {K}){C_RESET}")

        # Construct Manual Test Array
        # Frame 1: 1.0, 2.0, 3.0
        # Frame 2: 1.1, 2.1, 3.1
        # Frame 3: 1.2, 2.2, 3.2
        # Frame 4: 1.3, 2.3, 3.3
        full_test_data = [1.0, 2.0, 3.0, 1.1, 2.1, 3.1, 1.2, 2.2, 3.2, 1.3, 2.3, 3.3]
        
        if K == 4:
            test_input = np.array([full_test_data], dtype=np.float32)
        else:
            # Fallback for stateless or other stack sizes: slice the last K frames
            sliced_data = full_test_data[-(K * 3):]
            test_input = np.array([sliced_data], dtype=np.float32)

        # Execute feedforward pass
        raw_output = session.run(None, {input_name: test_input})[0][0]
        action_dim = len(raw_output)

        # Map raw outputs to policy variables matching production wrappers
        py_policy = {}
        if action_dim == 4:
            py_policy["recovery_rate"] = float(raw_output[0] * 0.5)
            py_policy["penalty_multiplier"] = float(raw_output[1] * 100.0)
            py_policy["sq_threshold"] = int(400 + (raw_output[2] * 400))
            py_policy["base_sampling_rate"] = float(raw_output[3])
        elif action_dim == 3:
            py_policy["recovery_rate"] = float(raw_output[0] * 0.5)
            py_policy["penalty_multiplier"] = float(raw_output[1] * 100.0)
            py_policy["sq_threshold"] = int(400 + (raw_output[2] * 400))
            py_policy["base_sampling_rate"] = 1.3  # Fallback to current instant sampling rate
        elif action_dim == 2:
            py_policy["recovery_rate"] = float(raw_output[0] * 0.5)
            py_policy["penalty_multiplier"] = float(raw_output[1] * 100.0)
            py_policy["sq_threshold"] = 650
            py_policy["base_sampling_rate"] = 0.05
        else:
            print(f"{C_ERROR}[ERROR] Model output dimension {action_dim} not supported.{C_RESET}")
            sys.exit(1)

        print(f"{C_SUCCESS}[SUCCESS] Python Inference completed successfully:{C_RESET}")
        for k, v in py_policy.items():
            print(f"  └── {k}: {v:.6f}")

    except Exception as py_err:
        print(f"{C_ERROR}[ERROR] Python inference failed: {py_err}{C_RESET}")
        sys.exit(1)

    # --------------------------------------------------------------------------
    # Step 3: Run C++ Side Standalone Inference
    # --------------------------------------------------------------------------
    try:
        print(f"{C_INFO}[*] Running C++ diagnostic binary in standalone test mode...{C_RESET}")
        cmd = [cpp_binary, "--test-onnx", onnx_path]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        cpp_policy = {}
        for line in result.stdout.splitlines():
            if line.startswith("[TEST] C++ Output"):
                parts = line.replace("[TEST] C++ Output ", "").split(":")
                if len(parts) == 2:
                    key = parts[0].strip()
                    val = float(parts[1].strip())
                    cpp_policy[key] = val

        if not cpp_policy:
            print(f"{C_ERROR}[ERROR] C++ standalone diagnostics returned empty results.{C_RESET}")
            print(f"[STDOUT]:\n{result.stdout}")
            sys.exit(1)

        print(f"{C_SUCCESS}[SUCCESS] C++ Standalone Inference completed successfully:{C_RESET}")
        for k, v in cpp_policy.items():
            print(f"  └── {k}: {v:.6f}")

    except Exception as cpp_err:
        print(f"{C_ERROR}[ERROR] C++ execution failed: {cpp_err}{C_RESET}")
        sys.exit(1)

    # --------------------------------------------------------------------------
    # Step 4: Perform Quantitative Error Difference Analysis
    # --------------------------------------------------------------------------
    print(f"\n{C_INFO}[*] Initiating Numeric Divergence Analysis (PyTorch/ONNX vs. C++):{C_RESET}")
    has_discrepancy = False
    tolerance = 1e-5

    for key in py_policy.keys():
        py_val = py_policy[key]
        cpp_val = cpp_policy.get(key, None)

        if cpp_val is None:
            print(f"  └── {key}: {C_ERROR}MISSING IN C++{C_RESET}")
            has_discrepancy = True
            continue

        diff = abs(py_val - cpp_val)
        if diff <= tolerance:
            print(f"  └── {key:<20}: Diff = {diff:<10.2e} {C_SUCCESS}[OK] (Aligned){C_RESET}")
        else:
            print(f"  └── {key:<20}: Diff = {diff:<10.2e} {C_ERROR}[FAIL] (Diverged){C_RESET}")
            has_discrepancy = True

    # --------------------------------------------------------------------------
    # Step 5: Final Report Output
    # --------------------------------------------------------------------------
    print("-" * 75)
    if has_discrepancy:
        print(f"{C_ERROR}[FAIL] Equivalence check failed! Numeric discrepancy exceeds tolerance threshold.{C_RESET}")
        print(f"{C_WARN}[NOTICE] Please review feature sorting/alignment, division by scaling factors, or memory layouts in C++.{C_RESET}")
        sys.exit(1)
    else:
        print(f"{C_SUCCESS}[PASS] Equivalence check passed! C++ and Python models are numerically identical.{C_RESET}")
        print(f"{C_INFO}[*] The C++ in-process ONNX deployment is aligned with Python training.{C_RESET}")
        sys.exit(0)

if __name__ == "__main__":
    main()
