# src/utils/network_io.py
import sys

class NetworkIOHelper:
    @staticmethod
    def parse_telemetry(data_str: str):
        """
        Parsing the string passed from C++: "avg_max_sum_sq,avg_budget,anomaly_rate"
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
    def serialize_policy(recovery: float, penalty: float, sq_thresh: int) -> bytes:
        """
            The AI decision is serialized into a C++-recognizable string: "recovery_rate,penalty_multiplier,sq_threshold\n"
        """
        payload = f"{recovery:.6f},{penalty:.6f},{int(sq_thresh)}\n"
        return payload.encode('utf-8')