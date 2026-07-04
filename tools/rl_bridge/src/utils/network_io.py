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
    def parse_telemetry(raw_bytes: bytes):
        """
        Parses incoming binary telemetry payload from C++ socket.
        Format: tp_count(I), tn_count(I), fp_count(I), fn_count(I), inspected_count(I), total_sq(Q), total_latency_ticks(Q), current_sampling_rate(f)
        Total size: 40 bytes.
        """
        import struct
        PAYLOAD_FORMAT = '<IIIIIQQf'
        try:
            if len(raw_bytes) < 40:
                return None
            unpacked = struct.unpack(PAYLOAD_FORMAT, raw_bytes[:40])
            return {
                "tp_count": unpacked[0],
                "tn_count": unpacked[1],
                "fp_count": unpacked[2],
                "fn_count": unpacked[3],
                "inspected_count": unpacked[4],
                "total_sq": unpacked[5],
                "total_latency_ticks": unpacked[6],
                "instant_sampling_rate": unpacked[7]
            }
        except Exception:
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