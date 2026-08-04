# engine/qos_multi.py
"""
Multi-Run QoSMultiPlotter Engine for IEEE ICC Evaluation
Processes 20-run trial datasets in outputs/multi_runs/, computes Mean ± Std Dev statistics,
and generates both pure Mean and Mean ± Std Dev console tables alongside publication plots.
"""

import os
import sys
import glob
import gc
import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from engine.base import BasePlotter
from engine.logger import LogStyle

class QoSMultiPlotter(BasePlotter):
    """
    Multi-Run Evaluation Engine: Computes 20-trial aggregated metrics (P99, P99.9, FNR, FPR, CPU, RAM)
    and renders Pooled CDF curves & Multi-Run timeline plots without altering legacy single-run outputs.
    """
    JITTER_THRESHOLD_MS = 50.0
    WARMUP = 100
    SPINNER = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

    def __init__(self, root_output_dir="outputs", use_onnx=True):
        # Override output plot directory to outputs/plots_multi_runs/
        super().__init__(root_output_dir)
        self.multi_dir = os.path.join(root_output_dir, "multi_runs")
        self.plots_out_dir = os.path.join(root_output_dir, "plots_multi_runs")
        self.stats_out_dir = os.path.join(root_output_dir, "stats_multi_runs")
        self.use_onnx = use_onnx

        os.makedirs(self.plots_out_dir, exist_ok=True)
        os.makedirs(self.stats_out_dir, exist_ok=True)

    def process_all_multi_runs(self):
        """
        Streaming single-pass parser with live dynamic heartbeat progress UI.
        Processes 440+ CSV files with strict RAM bounds (< 200MB) and live progress bars.
        """
        if not os.path.exists(self.multi_dir):
            LogStyle.log_error(f"Multi-run data directory missing: '{self.multi_dir}'")
            return None

        LogStyle.log_stage("[MULTI-RUN ENGINE] Discovering 20-trial telemetry datasets...")

        # Discover all CSV files
        pattern = os.path.join(self.multi_dir, "mode*", "run_*", "*", "*.csv")
        csv_files = glob.glob(pattern)
        total_files = len(csv_files)
        LogStyle.log_info(f"Discovered {total_files:,} telemetry files in '{self.multi_dir}'.")

        records = []
        t0 = time.time()

        print("\n\033[1;36m[*] STAGE 1/3: Parsing Telemetry Log Datasets...\033[0m")
        for idx, filepath in enumerate(csv_files, 1):
            rel_path = os.path.relpath(filepath, self.multi_dir)
            parts = rel_path.split(os.sep)
            if len(parts) < 4:
                continue

            mode_str = parts[0]      # e.g., mode1
            run_str = parts[1]       # e.g., run_01
            build_type = parts[2]    # e.g., unpatched
            filename = parts[3]      # e.g., qos_attack_1.0_mode1_onnx.csv

            filter_type = "unpatched_native"
            if "onnx" in filename:
                filter_type = "onnx_drl"
            elif "filtered" in filename:
                filter_type = "fsm_only"
            elif "full100" in filename:
                filter_type = "static_100"
            elif "codel" in filename:
                filter_type = "codel_aqm"

            rate = 0.0
            if "attack" in filename:
                try:
                    rate_str = filename.split("qos_attack_")[1].split("_mode")[0]
                    rate = float(rate_str)
                except Exception:
                    rate = 0.0

            # Single-pass CSV extraction for RAM efficiency
            rec = self._parse_single_csv_metrics(filepath)
            if rec:
                rec['mode'] = mode_str
                rec['run_id'] = run_str
                rec['build_type'] = build_type
                rec['filter_type'] = filter_type
                rec['rate'] = rate
                records.append(rec)

            # Live dynamic heartbeat progress bar update
            spin_char = self.SPINNER[idx % len(self.SPINNER)]
            pct = (idx * 100.0) / total_files
            short_fn = filename[:32]
            sys.stdout.write(f"\r  \033[36m[*] Parse Progress [{spin_char} ALIVE]:\033[0m [{idx:4d}/{total_files:4d}] | {pct:5.1f}% | File: {short_fn:<32}")
            sys.stdout.flush()

            if idx % 50 == 0:
                gc.collect()

        print(f"\n\033[32m[+] STAGE 1 COMPLETE: Parsed {len(records):,} telemetry CSV files in {time.time() - t0:.2f}s.\033[0m")

        # Also load baseline from outputs/csv_raw/unpatched/qos_baseline.csv if present
        baseline_path = os.path.join(self.root_output_dir, "csv_raw", "unpatched", "qos_baseline.csv")
        if os.path.exists(baseline_path):
            rec = self._parse_single_csv_metrics(baseline_path)
            if rec:
                rec['mode'] = "mode0"
                rec['run_id'] = "run_baseline"
                rec['build_type'] = "unpatched"
                rec['filter_type'] = "baseline"
                rec['rate'] = 0.0
                records.append(rec)

        if not records:
            LogStyle.log_error("No telemetry records processed.")
            return None

        print("\n\033[1;36m[*] STAGE 2/3: Computing 20-Trial Mean ± Std Dev Statistics Matrix...\033[0m")
        df_all = pd.DataFrame(records)

        # Compute Grouped Statistics
        summary_rows = []
        grouped = df_all.groupby(['mode', 'filter_type', 'rate', 'build_type'])
        total_groups = len(grouped)

        for g_idx, ((mode_val, filter_val, rate_val, build_val), group) in enumerate(grouped, 1):
            spin_char = self.SPINNER[g_idx % len(self.SPINNER)]
            sys.stdout.write(f"\r  \033[36m[*] Stats Computing [{spin_char} ALIVE]:\033[0m Group [{g_idx:2d}/{total_groups:2d}] Mode: {mode_val} | Filter: {filter_val} | Rate: {rate_val}%")
            sys.stdout.flush()

            n_trials = len(group)
            summary_rows.append({
                'mode': mode_val,
                'filter_type': filter_val,
                'rate_%': rate_val,
                'build_type': build_val,
                'trials': n_trials,
                'mean_p99_ms': group['p99'].mean(),
                'std_p99_ms': group['p99'].std() if n_trials > 1 else 0.0,
                'mean_p999_ms': group['p999'].mean(),
                'std_p999_ms': group['p999'].std() if n_trials > 1 else 0.0,
                'mean_fnr_%': group['fnr'].mean(),
                'std_fnr_%': group['fnr'].std() if n_trials > 1 else 0.0,
                'mean_fpr_%': group['fpr'].mean(),
                'std_fpr_%': group['fpr'].std() if n_trials > 1 else 0.0,
                'mean_cpu_s': group['cpu_s'].mean(),
                'std_cpu_s': group['cpu_s'].std() if n_trials > 1 else 0.0,
                'mean_ram_mb': group['ram_mb'].mean(),
                'std_ram_mb': group['ram_mb'].std() if n_trials > 1 else 0.0,
            })

        print(f"\n\033[32m[+] STAGE 2 COMPLETE: Aggregated {total_groups} evaluation groups.\033[0m")

        df_summary = pd.DataFrame(summary_rows).sort_values(by=['mode', 'filter_type', 'rate_%'])
        csv_out_path = os.path.join(self.stats_out_dir, "qos_multi_runs_aggregated.csv")
        df_summary.to_csv(csv_out_path, index=False)

        LogStyle.log_success(f"Aggregated 20-trial statistics saved to: '{csv_out_path}'")

        # Render Pooled CDF plots with live heartbeat progress
        print("\n\033[1;36m[*] STAGE 3/3: Rendering 20-Trial Pooled Latency CDF Plots...\033[0m")
        plot_targets = [(m, r) for m in [0, 1, 2] for r in [0.1, 0.5, 1.0, 5.0, 10.0]]
        for p_idx, (m, r) in enumerate(plot_targets, 1):
            spin_char = self.SPINNER[p_idx % len(self.SPINNER)]
            sys.stdout.write(f"\r  \033[36m[*] Plotting CDF [{spin_char} ALIVE]:\033[0m [{p_idx:2d}/{len(plot_targets):2d}] Mode: {m} | Rate: {r:.1f}%")
            sys.stdout.flush()
            self.plot_pooled_cdf(target_mode=m, target_rate=r)

        print(f"\n\033[32m[+] STAGE 3 COMPLETE: Rendered all 20-run pooled CDF plots in '{self.plots_out_dir}'.\033[0m")

        # Display BOTH Table Formats in Terminal Console for User Selection
        self._print_terminal_tables(df_summary)
        return df_summary

    def _parse_single_csv_metrics(self, filepath):
        try:
            df = pd.read_csv(filepath)
            if len(df) == 0:
                return None

            lat_col = 'latency_ns' if 'latency_ns' in df.columns else ('queue_delay_ns' if 'queue_delay_ns' in df.columns else 'delay_ns')
            lat_ms = df[lat_col] / 1e6
            lat_ms = lat_ms.iloc[self.WARMUP:]
            lat_ms = lat_ms[lat_ms < self.JITTER_THRESHOLD_MS]

            p95 = np.percentile(lat_ms, 95)
            p99 = np.percentile(lat_ms, 99)
            p999 = np.percentile(lat_ms, 99.9)

            total_malware = (df['is_malware'] == 1).sum()
            total_normal = (df['is_malware'] == 0).sum()

            tp = ((df['is_malware'] == 1) & (df['was_dropped'] == 1)).sum()
            fn = ((df['is_malware'] == 1) & (df['was_dropped'] == 0)).sum()
            fp = ((df['is_malware'] == 0) & (df['was_dropped'] == 1)).sum()

            fnr = (fn / total_malware * 100.0) if total_malware > 0 else 0.0
            fpr = (fp / total_normal * 100.0) if total_normal > 0 else 0.0

            cpu_s = df['cpu_time_sec'].max() if 'cpu_time_sec' in df.columns else 0.0
            ram_mb = df['ram_usage_mb'].max() if 'ram_usage_mb' in df.columns else 0.0

            return {
                'p95': p95,
                'p99': p99,
                'p999': p999,
                'fnr': fnr,
                'fpr': fpr,
                'cpu_s': cpu_s,
                'ram_mb': ram_mb
            }
        except Exception:
            return None

    def _print_terminal_tables(self, df_summary):
        """Prints Master Consolidated Table, Table I, Table II, and Table III for User Selection."""
        LogStyle.log_stage("\n" + "="*75)
        LogStyle.log_stage(" [IEEE ICC 20-TRIAL AGGREGATED METRICS - DUAL FORMAT OVERVIEW]")
        LogStyle.log_stage("="*75)

        onnx_df = df_summary[df_summary['filter_type'] == 'onnx_drl']

        # -------------------------------------------------------------
        # 0. MASTER CONSOLIDATED OVERVIEW TABLE
        # -------------------------------------------------------------
        print("\n\033[1;32m==========================================================================================================")
        print(" [MASTER CONSOLIDATED OVERVIEW TABLE]")
        print("==========================================================================================================\033[0m")
        display_cols = ['mode', 'filter_type', 'rate_%', 'trials', 'mean_p99_ms', 'std_p99_ms', 'mean_fnr_%', 'std_fnr_%', 'mean_cpu_s', 'mean_ram_mb']
        print(df_summary[display_cols].to_string(index=False, float_format="%.4f"))

        # -------------------------------------------------------------
        # FORMAT A: Pure Mean (Clean 4-Decimal Precision)
        # -------------------------------------------------------------
        print("\n\033[1;36m======================================================================")
        print(" [FORMAT A: PURE MEAN METRICS (Clean Table Output)]")
        print("======================================================================\033[0m")
        print("\n--- Table II: FNR Mean (%) Across Rates ---")
        piv_fnr = onnx_df.pivot(index='mode', columns='rate_%', values='mean_fnr_%')
        print(piv_fnr.to_string(float_format="%.4f"))

        print("\n--- Table I: P99 Tail Latency Mean (ms) Across Rates ---")
        piv_p99 = onnx_df.pivot(index='mode', columns='rate_%', values='mean_p99_ms')
        print(piv_p99.to_string(float_format="%.4f"))

        # -------------------------------------------------------------
        # FORMAT B: Mean ± Std Dev (Full Statistical Precision)
        # -------------------------------------------------------------
        print("\n\033[1;33m======================================================================")
        print(" [FORMAT B: MEAN ± STD DEV METRICS (Full LaTeX Table Format)]")
        print("======================================================================\033[0m")

        print("\n--- Table II LaTeX Rows: FNR (%) (Mean ± Std Dev) ---")
        for m in sorted(onnx_df['mode'].unique()):
            row_str = f"{m:<8}"
            for r in [0.1, 0.5, 1.0, 5.0, 10.0]:
                sub = onnx_df[(onnx_df['mode'] == m) & (onnx_df['rate_%'] == r)]
                if not sub.empty:
                    mean_v = sub['mean_fnr_%'].values[0]
                    std_v = sub['std_fnr_%'].values[0]
                    row_str += f" | {mean_v:.4f} ± {std_v:.4f}"
                else:
                    row_str += " | N/A"
            print(row_str)

        print("\n--- Table I LaTeX Rows: P99 Latency (ms) (Mean ± Std Dev) ---")
        for m in sorted(onnx_df['mode'].unique()):
            row_str = f"{m:<8}"
            for r in [0.1, 0.5, 1.0, 5.0, 10.0]:
                sub = onnx_df[(onnx_df['mode'] == m) & (onnx_df['rate_%'] == r)]
                if not sub.empty:
                    mean_v = sub['mean_p99_ms'].values[0]
                    std_v = sub['std_p99_ms'].values[0]
                    row_str += f" | {mean_v:.4f} ± {std_v:.4f}"
                else:
                    row_str += " | N/A"
            print(row_str)

        # -------------------------------------------------------------
        # TABLE III: Ablation Study Comparison (FSM-Only vs Static 100% vs ADAM DRL)
        # -------------------------------------------------------------
        print("\n\033[1;35m======================================================================")
        print(" [TABLE III: ABLATION STUDY COMPARISON - Mode 2 @ 0.1% & 10.0%]")
        print("======================================================================\033[0m")
        ablation_df = df_summary[(df_summary['mode'] == 'mode2') & (df_summary['rate_%'].isin([0.1, 10.0]))]
        if not ablation_df.empty:
            piv_abl_p99 = ablation_df.pivot(index='filter_type', columns='rate_%', values='mean_p99_ms')
            piv_abl_fnr = ablation_df.pivot(index='filter_type', columns='rate_%', values='mean_fnr_%')
            piv_abl_cpu = ablation_df.pivot(index='filter_type', columns='rate_%', values='mean_cpu_s')

            print("\n--- Ablation P99 Latency Mean (ms) ---")
            print(piv_abl_p99.to_string(float_format="%.4f"))

            print("\n--- Ablation FNR Mean (%) ---")
            print(piv_abl_fnr.to_string(float_format="%.4f"))

            print("\n--- Ablation CPU Time Mean (s) ---")
            print(piv_abl_cpu.to_string(float_format="%.4f"))

            print("\n--- Table III LaTeX Formatted Rows (Mean ± Std Dev) ---")
            for f_type in ['unpatched_native', 'fsm_only', 'static_100', 'onnx_drl']:
                sub = ablation_df[ablation_df['filter_type'] == f_type]
                if not sub.empty:
                    row_01 = sub[sub['rate_%'] == 0.1]
                    row_10 = sub[sub['rate_%'] == 10.0]
                    p99_01 = f"{row_01['mean_p99_ms'].values[0]:.4f} ± {row_01['std_p99_ms'].values[0]:.4f}" if not row_01.empty else "N/A"
                    fnr_01 = f"{row_01['mean_fnr_%'].values[0]:.4f} ± {row_01['std_fnr_%'].values[0]:.4f}" if not row_01.empty else "N/A"
                    p99_10 = f"{row_10['mean_p99_ms'].values[0]:.4f} ± {row_10['std_p99_ms'].values[0]:.4f}" if not row_10.empty else "N/A"
                    fnr_10 = f"{row_10['mean_fnr_%'].values[0]:.4f} ± {row_10['std_fnr_%'].values[0]:.4f}" if not row_10.empty else "N/A"
                    print(f"{f_type:<18} | Rate 0.1% P99: {p99_01:<18} | FNR: {fnr_01:<18} || Rate 10.0% P99: {p99_10:<18} | FNR: {fnr_10:<18}")

        print("\033[32m\n[+] Dual-format overview printed successfully! Select Format A or B for paper.\033[0m\n")

    def plot_pooled_cdf(self, target_mode=0, target_rate=10.0):
        """Plots Pooled 20-Trial Cumulative CDF Curve in outputs/plots_multi_runs/."""
        mode_str = f"mode{target_mode}"
        pattern = os.path.join(self.multi_dir, mode_str, "run_*", "unpatched", f"qos_attack_{target_rate:.1f}_mode{target_mode}_onnx.csv")
        files = glob.glob(pattern)

        if not files:
            return

        # Memory-efficient downsampled pooling
        pooled_samples = []
        for f in files[:20]:
            try:
                df = pd.read_csv(f)
                lat_col = 'latency_ns' if 'latency_ns' in df.columns else ('queue_delay_ns' if 'queue_delay_ns' in df.columns else 'delay_ns')
                lats = (df[lat_col] / 1e6).iloc[self.WARMUP:]
                lats = lats[lats < self.JITTER_THRESHOLD_MS]
                # Downsample 10,000 samples per trial for instant plotting without memory spikes
                if len(lats) > 10000:
                    lats = np.random.choice(lats, 10000, replace=False)
                pooled_samples.extend(lats)
            except Exception:
                continue

        if not pooled_samples:
            return

        pooled_samples = np.sort(pooled_samples)
        y = np.arange(1, len(pooled_samples) + 1) / len(pooled_samples)

        plt.figure(figsize=(7, 4.5))
        plt.plot(pooled_samples, y, label=f"ADAM (ONNX DRL 20-Run Pooled)", color='#1f77b4', linewidth=2.0)
        plt.axhline(0.99, color='red', linestyle='--', alpha=0.7, label='P99 Target')
        plt.xlabel('Queueing Latency (ms)')
        plt.ylabel('Cumulative Probability F(x)')
        plt.title(f'20-Run Pooled Latency CDF (Mode {target_mode} @ {target_rate}%)')
        plt.grid(True, alpha=0.3)
        plt.legend(loc='lower right')
        plt.tight_layout()

        out_img_path = os.path.join(self.plots_out_dir, f"cdf_pooled_mode{target_mode}_{target_rate:.1f}pct.png")
        plt.savefig(out_img_path, dpi=300)
        plt.close()
        LogStyle.log_success(f"Saved 20-Run Pooled CDF plot to: '{out_img_path}'")
