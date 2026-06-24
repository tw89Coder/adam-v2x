#!/usr/bin/env python3
# tools/analysis/audit_timeline_window.py
import os
import sys
import argparse
import pandas as pd

class LogStyle:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    STAGE = '\033[1;35m'
    INFO = '\033[1;36m'
    SUCCESS = '\033[1;32m'
    WARN = '\033[1;33m'
    ERROR = '\033[1;41;37m'
    LINE = '\033[38;5;240m'

    @classmethod
    def log_stage(cls, message): print(f"{cls.STAGE}[STAGE] {message}{cls.RESET}")
    @classmethod
    def log_info(cls, message): print(f"{cls.INFO}[INFO]  {message}{cls.RESET}")
    @classmethod
    def log_success(cls, message): print(f"{cls.SUCCESS}[SUCCESS] {message}{cls.RESET}")
    @classmethod
    def log_warn(cls, message): print(f"{cls.WARN}[WARN]  {message}{cls.RESET}")
    @classmethod
    def log_error(cls, message):
        print(f"\n{cls.ERROR}[FATAL ERROR] {message}{cls.RESET}\n")

class AnomalyAnalyzer:
    """
    Object-oriented analytical engine to inspect fine-grained QoS telemetry data
    within designated attack windows, extracting empirical drop rates and error matrices.
    """
    def __init__(self, root_output_dir, mode, rate):
        self.raw_dir = os.path.join(root_output_dir, "csv_raw")
        self.mode = mode
        self.rate = rate
        
        self.native_path = os.path.join(self.raw_dir, "unpatched", f"qos_attack_{rate}_mode{mode}.csv")
        self.filter_path = os.path.join(self.raw_dir, "unpatched", f"qos_attack_{rate}_mode{mode}_filtered.csv")

    def _load_dataframe(self, path):
        if not os.path.exists(path):
            LogStyle.log_error(f"Target metric frame missing: '{path}'")
            sys.exit(1)
        try:
            df = pd.read_csv(path)
            df['latency_ms'] = df['latency_ns'] / 1e6
            return df
        except Exception as e:
            LogStyle.log_error(f"Failed to ingest data frame at '{path}'. Context: {str(e)}")
            sys.exit(1)

    def run_audit(self):
        LogStyle.log_stage(f"Initiating Anomaly Window Audit for Mode {self.mode} @ {self.rate}% intensity...")
        
        df_native = self._load_dataframe(self.native_path)
        df_filter = self._load_dataframe(self.filter_path)

        total_records = max(df_native['packet_id'].max(), df_filter['packet_id'].max())
        
        # Define attack window boundaries based on protocol simulation context
        attack_start = int(total_records * 0.30)
        attack_end = int(total_records * 0.50)

        # Slice traffic matrices into localized verification regions
        nat_atk = df_native[(df_native['packet_id'].between(attack_start, attack_end)) & (df_native['is_malware'] == 0)]
        filt_atk = df_filter[(df_filter['packet_id'].between(attack_start, attack_end)) & (df_filter['was_dropped'] == 0)]
        
        nat_pre = df_native[(df_native['packet_id'] < attack_start) & (df_native['is_malware'] == 0)]
        filt_pre = df_filter[(df_filter['packet_id'] < attack_start) & (df_filter['was_dropped'] == 0)]

        dropped_packets = df_filter[(df_filter['packet_id'].between(attack_start, attack_end)) & (df_filter['was_dropped'] == 1)]
        total_in_window = len(df_filter[df_filter['packet_id'].between(attack_start, attack_end)])

        false_positives = df_filter[(df_filter['is_malware'] == 0) & (df_filter['was_dropped'] == 1)]
        total_benign = len(df_filter[df_filter['is_malware'] == 0])

        # Render structured console summary report
        print(LogStyle.LINE + "\n" + "="*65 + LogStyle.RESET)
        print(LogStyle.BOLD + " TIMELINE WINDOW AUDIT MATRIX SUMMARY" + LogStyle.RESET)
        print(LogStyle.LINE + "-"*65 + LogStyle.RESET)
        print(" [PRE-ATTACK STEADY STATE QUANTILES]")
        print(f"  Unpatched Native -> Median: {nat_pre['latency_ms'].median():.4f} ms | P99: {nat_pre['latency_ms'].quantile(0.99):.4f} ms")
        print(f"  FSM Pre-Filter   -> Median: {filt_pre['latency_ms'].median():.4f} ms | P99: {filt_pre['latency_ms'].quantile(0.99):.4f} ms")
        print("\n [ACTIVE ATTACK PHASE STATUS (Legitimate Traffic Vectors Only)]")
        print(f"  Unpatched Native -> Median: {nat_atk['latency_ms'].median():.4f} ms | P99: {nat_atk['latency_ms'].quantile(0.99):.4f} ms (n={len(nat_atk)})")
        print(f"  FSM Pre-Filter   -> Median: {filt_atk['latency_ms'].median():.4f} ms | P99: {filt_atk['latency_ms'].quantile(0.99):.4f} ms (n={len(filt_atk)})")
        print("\n [MITIGATION ENFORCEMENT EFFICIENCY RATIOS]")
        drop_rate = (100 * len(dropped_packets) / total_in_window) if total_in_window > 0 else 0.0
        fpr_rate = (100 * len(false_positives) / total_benign) if total_benign > 0 else 0.0
        print(f"  Intercepted Ingress Discards: {len(dropped_packets)} / {total_in_window} -> Drop Efficiency: {drop_rate:.1f}%")
        print(f"  Empirical False Positive Drop Rate: {len(false_positives)} / {total_benign} -> Matrix FPR: {fpr_rate:.2f}%")
        print(LogStyle.LINE + "="*65 + "\n" + LogStyle.RESET)
        LogStyle.log_success("Window validation diagnostics parsed successfully.")

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(script_dir))
    default_outputs = os.path.join(project_root, "outputs")

    parser = argparse.ArgumentParser(description="Industrial Timeline Anomaly Window Audit Tool.")
    parser.add_argument('--mode', type=int, choices=[0, 1, 2], default=1, help="Target simulation attack mode.")
    parser.add_argument('--rate', type=float, choices=[1.0, 5.0, 10.0], default=10.0, help="Target flood intensity rate.")
    parser.add_argument('--output-dir', type=str, default=default_outputs, help="Path to absolute outputs directory.")

    args = parser.parse_args()
    
    analyzer = AnomalyAnalyzer(root_output_dir=args.output_dir, mode=args.mode, rate=args.rate)
    analyzer.run_audit()

if __name__ == "__main__":
    main()