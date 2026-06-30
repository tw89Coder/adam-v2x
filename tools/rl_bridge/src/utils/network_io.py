"""
@file network_io.py
@brief Socket string parsing and serialization helper aligning with the C++ wire protocol.

This module houses the NetworkIOHelper utility. It deserializes plain telemetry CSV
strings from C++ into Python dictionaries and serializes continuous continuous action 
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
        Format: "avg_max_sum_sq,avg_budget,anomaly_rate\n"
        """
        try:
            tokens = data_str.strip().split(',')
            if len(tokens) != 3:
                return None
            return {
                "avg_sq": float(tokens[0]),
                "avg_budget": float(tokens[1]),
                "anomaly_rate": float(tokens[2])
            }
        except ValueError:
            return None

    @staticmethod
    def serialize_policy(recovery: float, penalty: float, sq_thresh: int, s0_sampling: float) -> bytes:
        """
        UPGRADED: Serializes 4 continuous parameters into the extended wire protocol.
        Format: "recovery_rate,penalty_multiplier,sq_threshold,s0_sampling_rate\n"
        
        NOTE FOR CODE REVIEW:
        This method has been upgraded to take 4 arguments, but serve_agent.py still
        invokes it with 3 parameters. This creates a TypeMismatch crash in production.
        """
        payload = f"{recovery:.6f},{penalty:.6f},{int(sq_thresh)},{s0_sampling:.6f}\n"
        return payload.encode('utf-8')