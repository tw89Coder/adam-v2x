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
import concurrent.futures
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

        print("\n[*] STAGE 1/4: Parsing Telemetry Log Datasets in Parallel...")
        
        def parse_file_job(filepath):
            rel_path = os.path.relpath(filepath, self.multi_dir)
            parts = rel_path.split(os.sep)
            if len(parts) < 4:
                return None

            mode_str = parts[0]
            run_str = parts[1]
            build_type = parts[2]
            filename = parts[3]

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

            if rate == 0.0 and filter_type == "unpatched_native":
                filter_type = "baseline"

            rec = self._parse_single_csv_metrics(filepath)
            if rec:
                rec['mode'] = mode_str
                rec['run_id'] = run_str
                rec['build_type'] = build_type
                rec['filter_type'] = filter_type
                rec['rate'] = rate
                rec['filepath'] = filepath
                rec['filename'] = filename
            return rec

        max_workers = min(os.cpu_count() or 4, 16)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(parse_file_job, fp) for fp in csv_files]
            for idx, future in enumerate(concurrent.futures.as_completed(futures), 1):
                try:
                    rec = future.result()
                    if rec:
                        records.append(rec)
                except Exception:
                    pass

                spin_char = self.SPINNER[idx % len(self.SPINNER)]
                pct = (idx * 100.0) / total_files
                sys.stdout.write(f"\r  [*] Parallel Parse Progress [{spin_char} ALIVE]: [{idx:4d}/{total_files:4d}] | {pct:5.1f}%")
                sys.stdout.flush()

        print(f"\n[+] STAGE 1 COMPLETE: Parsed {len(records):,} telemetry CSV files in {time.time() - t0:.2f}s using {max_workers} threads.")

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
                if transport_df is not None and not transport_df.empty and 'out_filename' in transport_df.columns:
                    transport_df = transport_df.drop_duplicates(subset=['out_filename'], keep='last')
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
            n_trials = len(group)
            cpu_s = 0.0
            std_cpu_s = 0.0
            ram_mb = np.nan
            std_ram_mb = np.nan

            # Direct calculation of CPU time from parsed per-file metadata headers across 20 trials
            if 'cpu_s' in group and group['cpu_s'].sum() > 0:
                cpu_s = round(float(group['cpu_s'].mean()), 4)
                std_cpu_s = round(float(group['cpu_s'].std()), 4) if n_trials > 1 else 0.0

            # Fallback lookup from transport summary for CPU if header metadata was absent in legacy files
            if cpu_s == 0.0 and transport_df is not None and not transport_df.empty:
                try:
                    mode_num = int(mode_val.replace("mode", "")) if "mode" in str(mode_val) else 0
                    f_mode = filter_mode_map.get(filter_val, 0)
                    
                    # Exact filter match
                    match = transport_df[
                        (transport_df['mode'].astype(int) == mode_num) & 
                        (np.isclose(transport_df['rate'].astype(float), float(rate_val))) & 
                        (transport_df['filter_mode'].astype(int) == f_mode)
                    ]
                    
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
                            cpu_s = round(float(match['cpu_time_sec'].mean()), 4)
                            if len(match) > 1:
                                std_cpu_s = round(float(match['cpu_time_sec'].std()), 4)
                except Exception:
                    pass

            # EXCLUSIVE pure production RAM lookup from outputs/pure_memory_runs/ ONLY (NO FALLBACKS!)
            pure_ram_dir = os.path.join(self.root_output_dir, "pure_memory_runs")
            if os.path.exists(pure_ram_dir):
                try:
                    pure_pattern = os.path.join(pure_ram_dir, mode_val, "run_*", "*", "*.csv")
                    p_files = glob.glob(pure_pattern)
                    matched_ram_vals = []
                    for pf in p_files:
                        fn = os.path.basename(pf)
                        is_match = False
                        if filter_val == 'onnx_drl' and 'onnx' in fn: is_match = True
                        elif filter_val == 'static_100' and 'full100' in fn: is_match = True
                        elif filter_val == 'fsm_only' and 'filtered' in fn: is_match = True
                        elif filter_val == 'codel_aqm' and 'codel' in fn: is_match = True
                        elif filter_val in ['unpatched_native', 'baseline']:
                            if 'baseline' in fn: is_match = True
                            elif 'attack' in fn and not any(k in fn for k in ['onnx', 'full100', 'filtered', 'codel']): is_match = True
                        
                        if is_match:
                            r_val = 0.0
                            if "attack" in fn:
                                try:
                                    r_val = float(fn.split("qos_attack_")[1].split("_mode")[0])
                                except Exception:
                                    r_val = 0.0
                            
                            if np.isclose(r_val, float(rate_val)):
                                rec_p = self._parse_single_csv_metrics(pf)
                                if rec_p and 'ram_mb' in rec_p and rec_p['ram_mb'] > 0:
                                    matched_ram_vals.append(rec_p['ram_mb'])

                    if matched_ram_vals:
                        ram_mb = round(float(np.mean(matched_ram_vals)), 2)
                        std_ram_mb = round(float(np.std(matched_ram_vals)), 2) if len(matched_ram_vals) > 1 else 0.0
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
                'std_cpu_s': std_cpu_s,
                'add_cpu_s': add_cpu_s,
                'mean_ram_mb': ram_mb,
                'std_ram_mb': std_ram_mb,
            })

        print(f"\n[+] STAGE 2 COMPLETE: Aggregated {total_groups} evaluation groups.")

        df_summary = pd.DataFrame(summary_rows).sort_values(by=['mode', 'filter_type', 'rate_%'])
        csv_out_path = os.path.join(self.stats_dir, "qos_multi_runs_aggregated.csv")
        df_summary.to_csv(csv_out_path, index=False)

        LogStyle.log_success(f"Aggregated 20-trial statistics saved to: '{csv_out_path}'")

        # Display Terminal Summary Tables immediately so user sees the table without waiting for plot rendering
        self._print_terminal_tables(df_summary)

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

        return df_summary

    def _parse_single_csv_metrics(self, filepath):
        try:
            # Fast header check to read METADATA comment and column structure
            cpu_s = 0.0
            ram_mb = 0.0
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                first_line = f.readline()
                if first_line.startswith('# METADATA:'):
                    meta_str = first_line.replace('# METADATA:', '').strip()
                    for kv in meta_str.split(','):
                        if '=' in kv:
                            k, v = kv.split('=', 1)
                            k = k.strip()
                            if k == 'cpu_time_sec':
                                cpu_s = float(v.strip())
                            elif k == 'peak_rss_kb':
                                ram_mb = float(v.strip()) / 1024.0
                    header_line = f.readline()
                else:
                    header_line = first_line

            headers = [h.strip() for h in header_line.split(',')]

            target_cols = [c for c in ['latency_ns', 'queue_delay_ns', 'delay_ns', 'is_malware', 'was_dropped', 'cpu_time_sec', 'ram_usage_mb'] if c in headers]
            dtypes = {}
            for c in target_cols:
                if c in ['is_malware', 'was_dropped']:
                    dtypes[c] = 'int8'
                elif c in ['latency_ns', 'queue_delay_ns', 'delay_ns']:
                    dtypes[c] = 'float64'

            if target_cols:
                try:
                    df = pd.read_csv(filepath, usecols=target_cols, dtype=dtypes, comment='#', engine='c')
                except Exception:
                    df = pd.DataFrame()
            else:
                df = pd.DataFrame()

            if len(df) == 0:
                if ram_mb > 0.0:
                    return {
                        'p95': 0.0,
                        'p99': 0.0,
                        'p999': 0.0,
                        'fnr': 0.0,
                        'fpr': 0.0,
                        'cpu_s': cpu_s,
                        'ram_mb': ram_mb
                    }
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

            if cpu_s == 0.0 and 'cpu_time_sec' in df.columns:
                cpu_s = df['cpu_time_sec'].max()
            if ram_mb == 0.0 and 'ram_usage_mb' in df.columns:
                ram_mb = df['ram_usage_mb'].max()

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
        """Prints Master Consolidated Table, Table I, Table II, and Table III with high-contrast ANSI colors."""
        C_RESET   = "\033[0m"
        C_BOLD    = "\033[1m"
        C_CYAN    = "\033[1;36m"  # ADAM ONNX DRL
        C_GREEN   = "\033[1;32m"  # FSM Only
        C_YELLOW  = "\033[1;33m"  # Static 100%
        C_RED     = "\033[1;31m"  # Unpatched Native Danger
        C_MAGENTA = "\033[1;35m"  # CoDel AQM
        C_WHITE   = "\033[1;37m"  # Peacetime Baseline

        color_map = {
            'baseline': C_WHITE,
            'unpatched_native': C_RED,
            'fsm_only': C_GREEN,
            'static_100': C_YELLOW,
            'onnx_drl': C_CYAN,
            'codel_aqm': C_MAGENTA,
        }

        print("\n" + C_BOLD + C_CYAN + "="*115 + C_RESET)
        print(C_BOLD + C_CYAN + " [IEEE ICC 20-TRIAL AGGREGATED METRICS - INDUSTRIAL HIGH-CONTRAST MANUSCRIPT TABLES]" + C_RESET)
        print(C_BOLD + C_CYAN + "="*115 + C_RESET)

        # -------------------------------------------------------------
        # 0. MASTER CONSOLIDATED OVERVIEW TABLE
        # -------------------------------------------------------------
        print("\n" + C_BOLD + C_YELLOW + "=====================================================================================================================" + C_RESET)
        print(C_BOLD + C_YELLOW + " [MASTER CONSOLIDATED OVERVIEW TABLE]" + C_RESET)
        print(C_BOLD + C_YELLOW + "=====================================================================================================================" + C_RESET)
        
        header_str = f"{'mode':<8} {'filter_type':<20} {'rate_%':<8} {'trials':<8} {'mean_p99_ms':<12} {'std_p99_ms':<12} {'mean_fnr_%':<12} {'std_fnr_%':<12} {'mean_cpu_s':<12} {'std_cpu_s':<12} {'add_cpu_s':<12} {'mean_ram_mb':<12} {'std_ram_mb':<12}"
        print(C_BOLD + header_str + C_RESET)
        print("-" * 155)

        for _, row in df_summary.iterrows():
            f_type = row['filter_type']
            c_code = color_map.get(f_type, C_RESET)
            row_line = f"{row['mode']:<8} {f_type:<20} {row['rate_%']:<8.4f} {int(row['trials']):<8} {row['mean_p99_ms']:<12.4f} {row['std_p99_ms']:<12.4f} {row['mean_fnr_%']:<12.4f} {row['std_fnr_%']:<12.4f} {row['mean_cpu_s']:<12.4f} {row['std_cpu_s']:<12.4f} {row['add_cpu_s']:<12.4f} {row['mean_ram_mb']:<12.2f} {row['std_ram_mb']:<12.2f}"
            print(c_code + row_line + C_RESET)

        # -------------------------------------------------------------
        # TABLE I: P99 TAIL LATENCY MANUSCRIPT GRID (Mean ± Std Dev)
        # -------------------------------------------------------------
        print("\n" + C_BOLD + C_CYAN + "=====================================================================================================================" + C_RESET)
        print(C_BOLD + C_CYAN + " [TABLE I: P99 TAIL LATENCY OVERVIEW (ms)] (Mean ± Std Dev Across 20 Trials)" + C_RESET)
        print(C_BOLD + C_CYAN + "=====================================================================================================================" + C_RESET)
        print(C_BOLD + f"{'Mode':<8} {'Mechanism':<20} {'0.1%':<22} {'0.5%':<22} {'1.0%':<22} {'5.0%':<22} {'10.0%':<22}" + C_RESET)
        print("-" * 130)

        for m in ['mode0', 'mode1', 'mode2']:
            sub_m = df_summary[df_summary['mode'] == m]
            if sub_m.empty: continue
            for f_type in ['baseline', 'unpatched_native', 'codel_aqm', 'fsm_only', 'static_100', 'onnx_drl']:
                sub_f = sub_m[sub_m['filter_type'] == f_type]
                if sub_f.empty: continue
                c_code = color_map.get(f_type, C_RESET)
                row_cells = []
                for r in [0.1, 0.5, 1.0, 5.0, 10.0]:
                    match_r = sub_f[np.isclose(sub_f['rate_%'].astype(float), r)]
                    if not match_r.empty:
                        m_val = match_r['mean_p99_ms'].values[0]
                        s_val = match_r['std_p99_ms'].values[0]
                        row_cells.append(f"{m_val:.4f} ± {s_val:.4f}")
                    else:
                        row_cells.append(f"{'-':^18}")
                cell_str = " | ".join([f"{c:<20}" for c in row_cells])
                print(f"{m:<8} " + c_code + f"{f_type:<20}" + C_RESET + " | " + cell_str)
            print("-" * 130)

        # -------------------------------------------------------------
        # TABLE II: FNR MALWARE LEAKAGE MANUSCRIPT GRID (Mean ± Std Dev)
        # -------------------------------------------------------------
        print("\n" + C_BOLD + C_GREEN + "=====================================================================================================================" + C_RESET)
        print(C_BOLD + C_GREEN + " [TABLE II: FNR MALWARE LEAKAGE OVERVIEW (%)] (Mean ± Std Dev Across 20 Trials)" + C_RESET)
        print(C_BOLD + C_GREEN + "=====================================================================================================================" + C_RESET)
        print(C_BOLD + f"{'Mode':<8} {'Mechanism':<20} {'0.1%':<22} {'0.5%':<22} {'1.0%':<22} {'5.0%':<22} {'10.0%':<22}" + C_RESET)
        print("-" * 130)

        for m in ['mode0', 'mode1', 'mode2']:
            sub_m = df_summary[df_summary['mode'] == m]
            if sub_m.empty: continue
            for f_type in ['baseline', 'unpatched_native', 'codel_aqm', 'fsm_only', 'static_100', 'onnx_drl']:
                sub_f = sub_m[sub_m['filter_type'] == f_type]
                if sub_f.empty: continue
                c_code = color_map.get(f_type, C_RESET)
                row_cells = []
                for r in [0.1, 0.5, 1.0, 5.0, 10.0]:
                    match_r = sub_f[np.isclose(sub_f['rate_%'].astype(float), r)]
                    if not match_r.empty:
                        m_val = match_r['mean_fnr_%'].values[0]
                        s_val = match_r['std_fnr_%'].values[0]
                        row_cells.append(f"{m_val:.4f} ± {s_val:.4f}")
                    else:
                        row_cells.append(f"{'-':^18}")
                cell_str = " | ".join([f"{c:<20}" for c in row_cells])
                print(f"{m:<8} " + c_code + f"{f_type:<20}" + C_RESET + " | " + cell_str)
            print("-" * 130)

        # -------------------------------------------------------------
        # TABLE III: ABLATION STUDY COMPARISON (Mode 2 @ 0.1% & 10.0%)
        # -------------------------------------------------------------
        print("\n" + C_BOLD + C_MAGENTA + "=====================================================================================================================" + C_RESET)
        print(C_BOLD + C_MAGENTA + " [TABLE III: ABLATION STUDY COMPARISON - Mode 2 @ 0.1% & 10.0%]" + C_RESET)
        print(C_BOLD + C_MAGENTA + "=====================================================================================================================" + C_RESET)
        ablation_df = df_summary[(df_summary['mode'] == 'mode2') & (df_summary['rate_%'].isin([0.1, 10.0]))]
        if not ablation_df.empty:
            print(C_BOLD + f"{'Mechanism':<20} | {'Rate 0.1% P99 (ms)':<22} | {'Rate 0.1% FNR (%)':<22} || {'Rate 10.0% P99 (ms)':<22} | {'Rate 10.0% FNR (%)':<22}" + C_RESET)
            print("-" * 125)
            for f_type in ['unpatched_native', 'fsm_only', 'static_100', 'onnx_drl']:
                sub = ablation_df[ablation_df['filter_type'] == f_type]
                if not sub.empty:
                    c_code = color_map.get(f_type, C_RESET)
                    row_01 = sub[np.isclose(sub['rate_%'].astype(float), 0.1)]
                    row_10 = sub[np.isclose(sub['rate_%'].astype(float), 10.0)]
                    p99_01 = f"{row_01['mean_p99_ms'].values[0]:.4f} ± {row_01['std_p99_ms'].values[0]:.4f}" if not row_01.empty else "-"
                    fnr_01 = f"{row_01['mean_fnr_%'].values[0]:.4f} ± {row_01['std_fnr_%'].values[0]:.4f}" if not row_01.empty else "-"
                    p99_10 = f"{row_10['mean_p99_ms'].values[0]:.4f} ± {row_10['std_p99_ms'].values[0]:.4f}" if not row_10.empty else "-"
                    fnr_10 = f"{row_10['mean_fnr_%'].values[0]:.4f} ± {row_10['std_fnr_%'].values[0]:.4f}" if not row_10.empty else "-"
                    print(c_code + f"{f_type:<20}" + C_RESET + f" | {p99_01:<22} | {fnr_01:<22} || {p99_10:<22} | {fnr_10:<22}")

        print(C_BOLD + C_CYAN + "\n[+] Multi-run evaluation, statistical aggregation, and publication graphics synthesis completed cleanly." + C_RESET)
