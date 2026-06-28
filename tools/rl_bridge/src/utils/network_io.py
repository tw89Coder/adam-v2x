# src/utils/network_io.py
import sys

class NetworkIOHelper:
    @staticmethod
    def parse_telemetry(data_str: str):
        """
        Parses incoming telemetry from C++: "avg_max_sum_sq,avg_budget,anomaly_rate"
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
        """
        payload = f"{recovery:.6f},{penalty:.6f},{int(sq_thresh)},{s0_sampling:.6f}\n"
        return payload.encode('utf-8')