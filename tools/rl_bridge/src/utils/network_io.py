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
        Parses incoming binary telemetry payload from C++ socket and calculates performance rates.
        Format: five counters (I), two accumulators (Q), three rates/budget
        values (f), FSM state, clean streak, and episode marker (I).
        Total size: 60 bytes.
        """
        import struct
        PAYLOAD_FORMAT = '<IIIIIQQfffIII'
        try:
            if len(raw_bytes) < 60:
                return None
            unpacked = struct.unpack(PAYLOAD_FORMAT, raw_bytes[:60])
            
            # Extract raw count fields
            tp = unpacked[0]
            tn = unpacked[1]
            fp = unpacked[2]
            fn = unpacked[3]
            inspected = unpacked[4]
            total_sq = unpacked[5]
            latency_ticks = unpacked[6]
            instant_sampling_rate = unpacked[7]
            base_sampling_rate = unpacked[8]
            current_budget = unpacked[9]
            fsm_state = unpacked[10]
            clean_streak = unpacked[11]
            episode_start = bool(unpacked[12])
            
            total_packets = tp + tn + fp + fn
            if total_packets == 0:
                total_packets = 1
                
            total_malware = tp + fn
            total_benign = fp + tn
            
            # Compute and return all metrics and rates
            return {
                "tp_count": tp,
                "tn_count": tn,
                "fp_count": fp,
                "fn_count": fn,
                "inspected_count": inspected,
                "total_sq": total_sq,
                "total_latency_ticks": latency_ticks,
                "instant_sampling_rate": instant_sampling_rate,
                "effective_sampling_rate": instant_sampling_rate,
                "base_sampling_rate": base_sampling_rate,
                "current_budget": current_budget,
                "fsm_state": fsm_state,
                "clean_streak": clean_streak,
                "episode_start": episode_start,
                
                # Computed rates
                "avg_sq": total_sq / total_packets,
                "anomaly_rate": (tp + fp) / total_packets,
                "true_anomaly_rate": total_malware / total_packets,
                "avg_budget": max(0.0, min(1.0, current_budget / 100.0)),
                "actual_inspection_rate": inspected / total_packets,
                
                "fpr": fp / total_benign if total_benign > 0 else 0.0,
                "fnr": fn / total_malware if total_malware > 0 else 0.0,
                "precision": tp / (tp + fp) if (tp + fp) > 0 else 0.0,
                "recall": tp / total_malware if total_malware > 0 else 0.0,
                "leakage_rate": fn / total_malware if total_malware > 0 else 0.0,
                # The C++ accumulator includes processing latency for every
                # packet, not only inspected packets.
                "avg_processing_latency_ticks": latency_ticks / total_packets
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
