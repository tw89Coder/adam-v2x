# engine/qos_multi.py
"""
Multi-Run QoSMultiPlotter Engine for IEEE ICC Evaluation.
Extends QoSPlotter to process 20-run trial datasets in outputs/multi_runs/,
selects representative median trials, computes 20-run aggregated statistics (Mean ± Std Dev),
and renders publication-grade vector (PDF, SVG) and raster (PNG) master CDF & timeline plots
strictly inside outputs/plots_multi_runs/ to protect original single-run outputs.
"""

import os
import sys
import glob
import gc
import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from engine.qos import QoSPlotter
from engine.logger import LogStyle

class QoSMultiPlotter(QoSPlotter):
    """
    Multi-Run Evaluation Engine: Inherits publication-grade graphics layout and export_figure
    from QoSPlotter, computes 20-run aggregated statistics, selects representative median runs,
    and exports vector PDF, SVG, and raster PNG figures into outputs/plots_multi_runs/.
    """
    SPINNER = ['-', '\\', '|', '/']

    def __init__(self, root_output_dir="outputs", use_onnx=True):
        super().__init__(root_output_dir=root_output_dir, use_onnx=use_onnx, no_patched=True)
        # Protect legacy single-run folders by pointing outputs to multi_runs subdirectories
        self.multi_dir = os.path.join(root_output_dir, "multi_runs")
        self.plots_dir = os.path.join(root_output_dir, "plots_multi_runs")
        self.stats_dir = os.path.join(root_output_dir, "stats_multi_runs")
        self._ensure_directory_exists(self.plots_dir)
        self._ensure_directory_exists(self.stats_dir)
        self.median_run_map = {}

    def _resolve_dataframe(self, environment, filename):
        """
        Resolves dataframe from representative median run in outputs/multi_runs/
        or falls back to raw single-run directory for baseline/codel files.
        """
        if filename in self.median_run_map:
            rep_path = self.median_run_map[filename]
            if os.path.exists(rep_path):
                df = self._load_csv_file(rep_path)
                lat_col = 'latency_ns' if 'latency_ns' in df.columns else ('queue_delay_ns' if 'queue_delay_ns' in df.columns else 'delay_ns')
                df['latency_ms'] = df[lat_col] / 1e6
                df = df.iloc[self.WARMUP:].reset_index(drop=True)
                df = df[df['latency_ms'] < self.JITTER_THRESHOLD_MS].reset_index(drop=True)
                return df

        # Fallback to single-run raw folder
        return super()._resolve_dataframe(environment, filename)

    def process_all_multi_runs(self):
        """
        Streaming single-pass parser with live heartbeat progress UI.
        Computes 20-run Mean ± Std Dev matrix and identifies representative median runs.
        """
        if not os.path.exists(self.multi_dir):
            LogStyle.log_error(f"Multi-run data directory missing: '{self.multi_dir}'")
            return None

        LogStyle.log_stage("[MULTI-RUN ENGINE] Discovering 20-trial telemetry datasets...")
        pattern = os.path.join(self.multi_dir, "mode*", "run_*", "*", "*.csv")
        csv_files = glob.glob(pattern)
        total_files = len(csv_files)
        LogStyle.log_info(f"Discovered {total_files:,} telemetry files in '{self.multi_dir}'.")

        records = []
        t0 = time.time()

        print("\n[*] STAGE 1/4: Parsing Telemetry Log Datasets...")
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

            rec = self._parse_single_csv_metrics(filepath)
            if rec:
                rec['mode'] = mode_str
                rec['run_id'] = run_str
                rec['build_type'] = build_type
                rec['filter_type'] = filter_type
                rec['rate'] = rate
                rec['filepath'] = filepath
                rec['filename'] = filename
                records.append(rec)

            spin_char = self.SPINNER[idx % len(self.SPINNER)]
            pct = (idx * 100.0) / total_files
            short_fn = filename[:32]
            sys.stdout.write(f"\r  [*] Parse Progress [{spin_char} ALIVE]: [{idx:4d}/{total_files:4d}] | {pct:5.1f}% | File: {short_fn:<32}")
            sys.stdout.flush()

            if idx % 50 == 0:
                gc.collect()

        print(f"\n[+] STAGE 1 COMPLETE: Parsed {len(records):,} telemetry CSV files in {time.time() - t0:.2f}s.")

        # Load baseline and CoDel AQM files from outputs/csv_raw/unpatched/
        raw_unpatched_dir = os.path.join(self.root_output_dir, "csv_raw", "unpatched")
        if os.path.exists(raw_unpatched_dir):
            baseline_path = os.path.join(raw_unpatched_dir, "qos_baseline.csv")
            if os.path.exists(baseline_path):
                rec = self._parse_single_csv_metrics(baseline_path)
                if rec:
                    rec['mode'] = "mode0"
                    rec['run_id'] = "run_baseline"
                    rec['build_type'] = "unpatched"
                    rec['filter_type'] = "baseline"
                    rec['rate'] = 0.0
                    rec['filepath'] = baseline_path
                    rec['filename'] = "qos_baseline.csv"
                    records.append(rec)

            codel_files = glob.glob(os.path.join(raw_unpatched_dir, "*codel.csv"))
            for cp in codel_files:
                fn = os.path.basename(cp)
                rate_v = 0.0
                if "attack" in fn:
                    try:
                        rate_v = float(fn.split("qos_attack_")[1].split("_mode")[0])
                    except Exception:
                        rate_v = 0.0
                rec = self._parse_single_csv_metrics(cp)
                if rec:
                    rec['mode'] = "mode0"
                    rec['run_id'] = "run_single"
                    rec['build_type'] = "unpatched"
                    rec['filter_type'] = "codel_aqm"
                    rec['rate'] = rate_v
                    rec['filepath'] = cp
                    rec['filename'] = fn
                    records.append(rec)

        if not records:
            LogStyle.log_error("No telemetry records processed.")
            return None

        print("\n[*] STAGE 2/4: Computing 20-Trial Aggregated Statistics & Selecting Median Runs...")
        df_all = pd.DataFrame(records)

        # Select median representative run for each filename configuration
        filename_groups = df_all.groupby('filename')
        for fname, fgroup in filename_groups:
            median_p99 = fgroup['p99'].median()
            fgroup_sorted = fgroup.iloc[(fgroup['p99'] - median_p99).abs().argsort()]
            best_row = fgroup_sorted.iloc[0]
            self.median_run_map[fname] = best_row['filepath']

        # Load transport summary CSV for CPU and RAM overhead integration
        summary_transport_path = os.path.join(self.root_output_dir, "stats", "udp_transport_summary.csv")
        transport_df = None
        if os.path.exists(summary_transport_path):
            try:
                transport_df = pd.read_csv(summary_transport_path, on_bad_lines='skip')
            except Exception:
                transport_df = None

        filter_mode_map = {
            'unpatched_native': 0,
            'fsm_only': 1,
            'static_100': 2,
            'onnx_drl': 3,
            'baseline': 0,
            'codel_aqm': 4
        }

        # Compute Grouped Statistics
        summary_rows = []
        grouped = df_all.groupby(['mode', 'filter_type', 'rate', 'build_type'])
        total_groups = len(grouped)

        for g_idx, ((mode_val, filter_val, rate_val, build_val), group) in enumerate(grouped, 1):
            spin_char = self.SPINNER[g_idx % len(self.SPINNER)]
            sys.stdout.write(f"\r  [*] Stats Computing [{spin_char} ALIVE]: Group [{g_idx:2d}/{total_groups:2d}] Mode: {mode_val} | Filter: {filter_val} | Rate: {rate_val}%")
            sys.stdout.flush()

            n_trials = len(group)

            # Lookup CPU and RAM from transport summary
            cpu_s = group['cpu_s'].mean()
            ram_mb = group['ram_mb'].mean()

            if transport_df is not None and not transport_df.empty:
                try:
                    mode_num = int(mode_val.replace("mode", "")) if "mode" in str(mode_val) else 0
                    f_mode = filter_mode_map.get(filter_val, 0)
                    
                    # Exact filter match
                    match = transport_df[
                        (transport_df['mode'].astype(int) == mode_num) & 
                        (np.isclose(transport_df['rate'].astype(float), float(rate_val))) & 
                        (transport_df['filter_mode'].astype(int) == f_mode)
                    ]
                    
                    # Refine by filename pattern if available
                    if filter_val == 'static_100':
                        sub_m = match[match['out_filename'].astype(str).str.contains("full100")]
                        if not sub_m.empty: match = sub_m
                    elif filter_val == 'fsm_only':
                        sub_m = match[match['out_filename'].astype(str).str.contains("filtered")]
                        if not sub_m.empty: match = sub_m
                    elif filter_val == 'onnx_drl':
                        sub_m = match[match['out_filename'].astype(str).str.contains("onnx")]
                        if not sub_m.empty: match = sub_m
                    elif filter_val == 'codel_aqm':
                        sub_m = match[match['out_filename'].astype(str).str.contains("codel")]
                        if not sub_m.empty: match = sub_m

                    if not match.empty:
                        if 'cpu_time_sec' in match and match['cpu_time_sec'].notnull().any():
                            cpu_s = round(float(match['cpu_time_sec'].median()), 4)
                        if 'peak_rss_kb' in match and match['peak_rss_kb'].notnull().any():
                            ram_mb = round(float(match['peak_rss_kb'].median()) / 1024.0, 2)
                except Exception:
                    pass

            # Base Peacetime Baseline CPU Overhead = 56.3685 s
            base_cpu_overhead = 56.3685
            add_cpu_s = round(max(0.0, cpu_s - base_cpu_overhead), 4) if cpu_s > 0.0 else 0.0

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
                'mean_cpu_s': cpu_s,
                'add_cpu_s': add_cpu_s,
                'mean_ram_mb': ram_mb,
            })

        print(f"\n[+] STAGE 2 COMPLETE: Aggregated {total_groups} evaluation groups.")

        df_summary = pd.DataFrame(summary_rows).sort_values(by=['mode', 'filter_type', 'rate_%'])
        csv_out_path = os.path.join(self.stats_dir, "qos_multi_runs_aggregated.csv")
        df_summary.to_csv(csv_out_path, index=False)

        LogStyle.log_success(f"Aggregated 20-trial statistics saved to: '{csv_out_path}'")

        # Render Publication-Grade Master Plots (PDF, SVG, PNG)
        print("\n[*] STAGE 3/4: Rendering Publication Vector (PDF, SVG) & Raster (PNG) Master Plots...")
        plot_targets = [(m, r) for m in [0, 1, 2] for r in [0.1, 0.5, 1.0, 5.0, 10.0]]
        for p_idx, (m, r) in enumerate(plot_targets, 1):
            spin_char = self.SPINNER[p_idx % len(self.SPINNER)]
            sys.stdout.write(f"\r  [*] Plotting Master Suite [{spin_char} ALIVE]: [{p_idx:2d}/{len(plot_targets):2d}] Mode: {m} | Rate: {r:.1f}%")
            sys.stdout.flush()
            self.plot_master_cdf(target_mode=m, target_rate=r)

        print(f"\n[+] STAGE 3 COMPLETE: Rendered all publication CDF & Jitter master plots in '{self.plots_dir}'.")

        # Render Timeline Traces
        print("\n[*] STAGE 4/4: Rendering Temporal Attack Timeline Traces...")
        self.plot_pulse_timeline()
        self.plot_periodic_timeline()
        print(f"\n[+] STAGE 4 COMPLETE: Rendered Pulse & Periodic attack timeline traces.")

        # Display Terminal Summary Tables
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
        print("\n=====================================================================================================================")
        print(" [MASTER CONSOLIDATED OVERVIEW TABLE]")
        print("=====================================================================================================================")
        display_cols = ['mode', 'filter_type', 'rate_%', 'trials', 'mean_p99_ms', 'std_p99_ms', 'mean_fnr_%', 'std_fnr_%', 'mean_cpu_s', 'add_cpu_s', 'mean_ram_mb']
        print(df_summary[display_cols].to_string(index=False, float_format="%.4f"))

        # -------------------------------------------------------------
        # FORMAT A: Pure Mean (Clean 4-Decimal Precision)
        # -------------------------------------------------------------
        print("\n======================================================================")
        print(" [FORMAT A: PURE MEAN METRICS (Clean Table Output)]")
        print("======================================================================")
        print("\n--- Table II: FNR Mean (%) Across Rates ---")
        piv_fnr = onnx_df.pivot(index='mode', columns='rate_%', values='mean_fnr_%')
        print(piv_fnr.to_string(float_format="%.4f"))

        print("\n--- Table I: P99 Tail Latency Mean (ms) Across Rates ---")
        piv_p99 = onnx_df.pivot(index='mode', columns='rate_%', values='mean_p99_ms')
        print(piv_p99.to_string(float_format="%.4f"))

        # -------------------------------------------------------------
        # FORMAT B: Mean ± Std Dev (Full Statistical Precision)
        # -------------------------------------------------------------
        print("\n======================================================================")
        print(" [FORMAT B: MEAN ± STD DEV METRICS (Full LaTeX Table Format)]")
        print("======================================================================")

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
        print("\n======================================================================")
        print(" [TABLE III: ABLATION STUDY COMPARISON - Mode 2 @ 0.1% & 10.0%]")
        print("======================================================================")
        ablation_df = df_summary[(df_summary['mode'] == 'mode2') & (df_summary['rate_%'].isin([0.1, 10.0]))]
        if not ablation_df.empty:
            piv_abl_p99 = ablation_df.pivot(index='filter_type', columns='rate_%', values='mean_p99_ms')
            piv_abl_fnr = ablation_df.pivot(index='filter_type', columns='rate_%', values='mean_fnr_%')
            piv_abl_cpu = ablation_df.pivot(index='filter_type', columns='rate_%', values='mean_cpu_s')
            piv_abl_add = ablation_df.pivot(index='filter_type', columns='rate_%', values='add_cpu_s')

            print("\n--- Ablation P99 Latency Mean (ms) ---")
            print(piv_abl_p99.to_string(float_format="%.4f"))

            print("\n--- Ablation FNR Mean (%) ---")
            print(piv_abl_fnr.to_string(float_format="%.4f"))

            print("\n--- Ablation Total Measured CPU Time (s) ---")
            print(piv_abl_cpu.to_string(float_format="%.4f"))

            print("\n--- Ablation Additional Inspection CPU Overhead Delta-CPU (s) ---")
            print(piv_abl_add.to_string(float_format="%.4f"))

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

        LogStyle.log_success("\n[+] Multi-run evaluation, statistical aggregation, and publication graphics synthesis completed cleanly.")
