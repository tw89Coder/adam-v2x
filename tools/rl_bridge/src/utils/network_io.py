"""
@file network_io.py
@brief Socket string parsing and serialization helper aligning with the C++ wire protocol.

This module houses the NetworkIOHelper utility. It deserializes plain telemetry CSV
strings from C++ into Python dictionaries and serializes continuous action 
parameters into comma-separated output wire strings.
"""

import sys

class NetworkIOHelper:
    """
    Utility class handling IPC wire serialization/deserialization.
    """
    @staticmethod
    def parse_telemetry(data_str: str):
        """
        Parses incoming telemetry CSV from C++ socket.
        Format: "avg_max_sum_sq,instant_sampling_rate,anomaly_rate[,true_anomaly_rate]\n"
        """
        try:
            tokens = data_str.strip().split(',')
            if len(tokens) < 3:
                return None
            return {
                "avg_sq": float(tokens[0]),
                "avg_budget": float(tokens[1]),           # Keep for backward compatibility with older PPO envs
                "instant_sampling_rate": float(tokens[1]),  # Direct mapping of the second field
                "anomaly_rate": float(tokens[2]),
                "true_anomaly_rate": float(tokens[3]) if len(tokens) >= 4 else 0.0
            }
        except ValueError:
            return None

    @staticmethod
    def serialize_policy(parameters: list) -> bytes:
        """
        Serializes a list of continuous policy parameters dynamically into the wire protocol.
        Format: "val_0,val_1,val_2,...\n"
        """
        tokens = []
        for val in parameters:
            if isinstance(val, (int, bool)):
                tokens.append(str(int(val)))
            elif isinstance(val, float):
                tokens.append(f"{val:.6f}")
            else:
                tokens.append(str(val))
        
        payload = ",".join(tokens) + "\n"
        return payload.encode('utf-8')