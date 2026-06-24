#!/usr/bin/env python3
# tools/analysis/calculate_structural_signal.py
import os
import sys
import argparse
import collections

class LogStyle:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    STAGE = '\033[1;35m'
    SUCCESS = '\033[1;32m'
    ERROR = '\033[1;41;37m'
    LINE = '\033[38;5;240m'

    @classmethod
    def log_stage(cls, message): print(f"{cls.STAGE}[STAGE] {message}{cls.RESET}")
    @classmethod
    def log_success(cls, message): print(f"{cls.SUCCESS}[SUCCESS] {message}{cls.RESET}")
    @classmethod
    def log_error(cls, message): print(f"\n{cls.ERROR}[FATAL ERROR] {message}{cls.RESET}\n")

class SignalComplexityAnalyzer:
    """
    Computes packet structural complexity metrics utilizing sliding-window information entropy
    and the second frequency moment (F2 / SQ signal values) over raw binary payloads.
    """
    def __init__(self, window_size=64):
        self.window_size = window_size

    def calculate_max_sq(self, filepath):
        if not os.path.exists(filepath):
            LogStyle.log_error(f"Binary payload target file missing: '{filepath}'")
            return None

        with open(filepath, 'rb') as f:
            payload = f.read()

        if len(payload) < self.window_size:
            counts = collections.Counter(payload)
            return sum(count ** 2 for count in counts.values())

        max_sq = 0
        for i in range(len(payload) - self.window_size + 1):
            window = payload[i : i + self.window_size]
            counts = collections.Counter(window)
            current_sq = sum(count ** 2 for count in counts.values())
            if current_sq > max_sq:
                max_sq = current_sq
                
        return max_sq

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(script_dir))

    # Adaptive path layout configuration supporting root paths and legacy paths
    default_cam = os.path.join(project_root, "inputs", "base_packets", "cam_v3_certificate.dat")
    legacy_cam = os.path.join(project_root, "vanetza_unpatched", "tools", "qos-harness", "input", "cam_v3_certificate.dat")
    
    default_poc = os.path.join(project_root, "inputs", "attack_vectors", "malware", "poc_mtu_limit.bin")
    legacy_poc = os.path.join(project_root, "vanetza_unpatched", "tools", "qos-harness", "input-malware", "poc_mtu_limit.bin")

    parser = argparse.ArgumentParser(description="Parser Structural Signal (SQ / F2 Moment) Complexity Analyzer.")
    parser.add_argument('--file', type=str, help="Scan a single explicit raw binary payload file path.")
    parser.add_argument('--window', type=int, default=64, help="Sliding validation evaluation window byte size.")
    
    args = parser.parse_args()
    analyzer = SignalComplexityAnalyzer(window_size=args.window)

    print(LogStyle.LINE + "="*65 + LogStyle.RESET)
    print(LogStyle.BOLD + " PARSER STRUCTURE SIGNAL (SQ) EXPLORATION MATRIX" + LogStyle.RESET)
    print(LogStyle.LINE + "-"*65 + LogStyle.RESET)

    if args.file:
        LogStyle.log_stage(f"Evaluating localized target payload: {args.file}")
        sq_val = analyzer.calculate_max_sq(args.file)
        if sq_val is not None:
            print(f" -> Computed Maximum SQ value: {sq_val}")
    else:
        # Resolve target files with multi-tier fallback routing paths
        cam_target = default_cam if os.path.exists(default_cam) else legacy_cam
        poc_target = default_poc if os.path.exists(default_poc) else legacy_poc

        print(f" [1] Scanning Legitimate Baseline Packet Track:\n     Path: {cam_target}")
        cam_sq = analyzer.calculate_max_sq(cam_target)
        if cam_sq is not None:
            print(f"     -> Max SQ of legitimate CAM: {cam_sq}")

        print(f"\n [2] Scanning High-Potency Volumetric Exploit Vector Payload:\n     Path: {poc_target}")
        poc_sq = analyzer.calculate_max_sq(poc_target)
        if poc_sq is not None:
            print(f"     -> Max SQ of malicious PoC: {poc_sq}")
            
    print(LogStyle.LINE + "="*65 + LogStyle.RESET)
    LogStyle.log_success("Structural complexity calculation sequence complete.")

if __name__ == "__main__":
    main()