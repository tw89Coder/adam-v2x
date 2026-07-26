#!/usr/bin/env python3
"""
@file onnx_server.py
@brief Lightweight Python ONNX Runtime Bridge Server.
Loads ONNX model (v2x_agent_dqn.onnx) and serves policy inference over TCP socket (127.0.0.1:8080) for 32-bit ARM environments.
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

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(PROJECT_ROOT, "checkpoints", "v2x_agent_dqn.onnx")

if not os.path.exists(MODEL_PATH):
    print(f"[FATAL] ONNX Model file not found at: {MODEL_PATH}")
    sys.exit(1)

print(f"[+] Loading ONNX model from: {MODEL_PATH}")
session = ort.InferenceSession(MODEL_PATH)
input_name = session.get_inputs()[0].name
action_map = [-0.20, -0.10, 0.0, 0.10, 0.20]

server_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_fd.bind(("127.0.0.1", 8080))
server_fd.listen(1)

print(f"======================================================================")
print(f"       PYTHON ONNX RUNTIME IPC BRIDGE ACTIVE (127.0.0.1:8080)")
print(f"======================================================================")
print(f"  ├── Model Path       : {MODEL_PATH}")
print(f"  ├── Action Map Size  : {len(action_map)} discrete actions")
print(f"  └── Execution Status : WAITING FOR C++ HARNESS CONNECTION...")
print(f"======================================================================\n")

while True:
    try:
        conn, addr = server_fd.accept()
        print(f"[+] C++ QoS Harness connected from {addr[0]}:{addr[1]}")
        
        current_sampling_rate = 0.10
        
        while True:
            # Wire protocol: Receive PacketTelemetry / Window summary struct
            # Each telemetry window sends 48 bytes (or window signal)
            data = conn.recv(1024)
            if not data:
                print("[-] Client disconnected. Waiting for next session...")
                break

            # Infer state observation: [norm_size, norm_sq, anomaly_rate]
            # If payload length matches telemetry, extract features:
            if len(data) >= 12:
                features = np.frombuffer(data[:12], dtype=np.float32).reshape(1, 3)
            else:
                features = np.array([[0.20, 0.01, 0.001]], dtype=np.float32)

            # Run Python ONNX Runtime inference pass
            outputs = session.run(None, {input_name: features})
            q_values = outputs[0][0]
            best_action_idx = int(np.argmax(q_values))
            delta = action_map[best_action_idx]

            current_sampling_rate = max(0.05, min(1.0, current_sampling_rate + delta))

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
