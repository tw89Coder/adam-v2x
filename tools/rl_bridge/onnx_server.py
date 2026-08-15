#!/usr/bin/env python3
"""
@file onnx_server.py
@brief Lightweight Python ONNX Runtime Bridge Server.
Loads ONNX model (v2x_agent_dqn.onnx) and serves policy inference over TCP socket (127.0.0.1:8080) for 32-bit ARM environments.
100% mirrors C++ RLBridge::run_onnx_inference history buffer and policy mapping.
"""

import os
import sys
import socket
import struct
import numpy as np

try:
    import onnxruntime as ort
except ImportError:
    print("[FATAL] Python 'onnxruntime' is not installed in the virtualenv.")
    print("[FATAL] Please run: pip install onnxruntime")
    sys.exit(1)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL_PATH = os.path.join(PROJECT_ROOT, "checkpoints", "v2x_agent_dqn.onnx")

if not os.path.exists(MODEL_PATH):
    print(f"[FATAL] ONNX Model file not found at: {MODEL_PATH}")
    sys.exit(1)

print(f"[+] Loading ONNX model from: {MODEL_PATH}")
session = ort.InferenceSession(MODEL_PATH)
input_meta = session.get_inputs()[0]
input_name = input_meta.name
input_shape = input_meta.shape

# Dynamically parse expected input dimension (e.g. 12 for frame_stack=4 x 3 features)
expected_dim = 12
if len(input_shape) > 1 and isinstance(input_shape[1], int):
    expected_dim = input_shape[1]

FEATURE_DIM = 3
K = expected_dim // FEATURE_DIM

print(f"[+] ONNX Input Tensor: '{input_name}' | Expected Dim: {expected_dim} (K={K} frames x {FEATURE_DIM} features)")

action_map = [-0.10, -0.05, 0.0, 0.05, 0.10]

server_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_fd.bind(("127.0.0.1", 8080))
server_fd.listen(1)

print(f"======================================================================")
print(f"       PYTHON ONNX RUNTIME IPC BRIDGE ACTIVE (127.0.0.1:8080)")
print(f"======================================================================")
print(f"  ├── Model Path       : {MODEL_PATH}")
print(f"  ├── Input Dim        : {expected_dim} features (K={K})")
print(f"  ├── Action Map Size  : {len(action_map)} discrete actions")
print(f"  └── Execution Status : WAITING FOR C++ HARNESS CONNECTION...")
print(f"======================================================================\n")

while True:
    try:
        conn, addr = server_fd.accept()
        
        current_sampling_rate = 0.50
        history_buffer = np.zeros((1, expected_dim), dtype=np.float32)
        history_initialized = False
        
        while True:
            # Wire protocol: Receive PacketTelemetry / Window summary struct
            data = conn.recv(1024)
            if not data:
                break

            # Parse 3 features: [norm_size, norm_sq, anomaly_rate]
            if len(data) >= 12:
                cur_feat = np.frombuffer(data[:12], dtype=np.float32)[:3]
            else:
                cur_feat = np.array([0.20, 0.01, 0.001], dtype=np.float32)

            # 100% Mirror C++ RLBridge::run_onnx_inference frame history buffer logic
            if not history_initialized:
                for i in range(K):
                    history_buffer[0, i * FEATURE_DIM : (i + 1) * FEATURE_DIM] = cur_feat
                history_initialized = True
            else:
                if K > 1:
                    history_buffer[0, :-FEATURE_DIM] = history_buffer[0, FEATURE_DIM:]
                    history_buffer[0, -FEATURE_DIM:] = cur_feat
                else:
                    history_buffer[0, :FEATURE_DIM] = cur_feat

            # Execute ONNX model inference feedforward pass
            outputs = session.run(None, {input_name: history_buffer})
            float_output = outputs[0][0]
            
            # 100% Mirror C++ RLBridge::run_onnx_inference algorithm mapping
            if len(float_output) == len(action_map):
                best_action_idx = int(np.argmax(float_output))
                delta = action_map[best_action_idx]
                current_sampling_rate = max(0.05, min(1.0, current_sampling_rate + delta))
            elif len(float_output) == 4:
                current_sampling_rate = float(float_output[3])

            # Send back Policy parameters struct (4 floats: recovery, penalty, sq_thresh, base_sampling_rate)
            reply = struct.pack("ffff", 0.05, 50.0, 600.0, float(current_sampling_rate))
            conn.sendall(reply)
            
        conn.close()
    except KeyboardInterrupt:
        print("\n[*] Python ONNX Server shutting down gracefully.")
        break
    except Exception as e:
        print(f"[ERROR] Session error: {e}")
        continue
