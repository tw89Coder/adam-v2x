# engine/qos.py
import os
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from engine.base import BasePlotter
from engine.logger import LogStyle

class QoSPlotter(BasePlotter):
    """
    Evaluates multi-scenario Quality of Service indicators, processes false positive
    bounds, compiles comparative performance summaries, and renders execution timelines.
    """
    WARMUP = 50
    JITTER_THRESHOLD_MS = 5.0
    MODES = [0, 1, 2]
    RATES = [1.0, 5.0, 10.0]

    def __init__(self, root_output_dir="outputs"):
        super().__init__(root_output_dir)
        self.raw_dir = os.path.join(root_output_dir, "csv_raw")

    def _resolve_dataframe(self, environment, filename):
        target_path = os.path.join(self.raw_dir, environment, filename)
        if not os.path.exists(target_path):
            return None
        
        df = self._load_csv_file(target_path)
        df['latency_ms'] = df['latency_ns'] / 1e6
        df = df.iloc[self.WARMUP:].reset_index(drop=True)
        
        # Apply strict OS scheduling noise filtration pass
        before = len(df)
        df = df[df['latency_ms'] < self.JITTER_THRESHOLD_MS].reset_index(drop=True)
        after = len(df)
        
        if before != after:
            LogStyle.log_info(f"Filtered {before - after} jitter spikes from [{environment}/{filename}].")
        return df

    def _calculate_security_vectors(self, df):
        if 'was_dropped' not in df.columns or 'is_malware' not in df.columns:
            return 'N/A', 'N/A'
        
        tp = len(df[(df['is_malware'] == 1) & (df['was_dropped'] == 1)])
        fp = len(df[(df['is_malware'] == 0) & (df['was_dropped'] == 1)])
        tn = len(df[(df['is_malware'] == 0) & (df['was_dropped'] == 0)])
        fn = len(df[(df['is_malware'] == 1) & (df['was_dropped'] == 0)])

        fpr = round((fp / (fp + tn)) * 100.0, 4) if (fp + tn) > 0 else 0.0
        fnr = round((fn / (fn + tp)) * 100.0, 4) if (fn + tp) > 0 else 0.0
        return fpr, fnr

    def _compute_stats(self, df, is_filtered=False):
        if df is None or df.empty:
            return None
        
        df_admitted = df[df['was_dropped'] == 0].reset_index(drop=True) if (is_filtered and 'was_dropped' in df.columns) else df
        if df_admitted.empty:
            return None

        fpr, fnr = self._calculate_security_vectors(df) if is_filtered else ('N/A', 'N/A')
        return {
            "Mean_ms":   round(df_admitted['latency_ms'].mean(), 4),
            "Median_ms": round(df_admitted['latency_ms'].median(), 4),
            "P99_ms":    round(df_admitted['latency_ms'].quantile(0.99), 4),
            "P99.9_ms":  round(df_admitted['latency_ms'].quantile(0.999), 4),
            "Max_ms":    round(df_admitted['latency_ms'].max(), 4),
            "FPR_%":     fpr,
            "FNR_%":     fnr,
        }

    def compute_all_combinations_stats(self):
        LogStyle.log_stage("Compiling Combined Statistical Matrix across configurations...")
        matrix_rows = []

        # Graceful evaluation wrapper for optional baseline profiles
        df_base = self._resolve_dataframe('unpatched', 'qos_attack_0.0_mode0.csv')
        if df_base is None:
            df_base = self._resolve_dataframe('unpatched', 'qos_baseline.csv')
            
        base_stats = self._compute_stats(df_base, is_filtered=False)
        if base_stats:
            matrix_rows.append({"Scenario": "Baseline Optimal", "Env": "unpatched", "Mode": "N/A", "Rate": 0.0, **base_stats})
        else:
            LogStyle.log_warn("Target baseline verification data framework unavailable. Evaluation skipped.")

        for mode in self.MODES:
            for rate in self.RATES:
                scenarios = [
                    ('unpatched', f'qos_attack_{rate}_mode{mode}.csv',          'Unpatched Native',   False),
                    ('unpatched', f'qos_attack_{rate}_mode{mode}_filtered.csv', 'Unpatched Filtered', True),
                    ('patched',   f'qos_attack_{rate}_mode{mode}.csv',          'Patched Native',     False),
                    ('patched',   f'qos_attack_{rate}_mode{mode}_filtered.csv', 'Patched Filtered',   True),
                ]
                for env, filename, label, is_filt in scenarios:
                    df = self._resolve_dataframe(env, filename)
                    res = self._compute_stats(df, is_filtered=is_filt)
                    if res:
                        matrix_rows.append({
                            "Scenario": f"{label} | M{mode} | {rate}%", "Env": env, "Mode": f"mode{mode}", "Rate": rate, **res
                        })

        if not matrix_rows:
            LogStyle.log_error("No actionable QoS analytical matrices identified.")
            return

        summary_df = pd.DataFrame(matrix_rows)
        self._ensure_directory_exists(self.stats_dir)
        csv_out_path = os.path.join(self.stats_dir, "qos_all_combinations.csv")
        summary_df.to_csv(csv_out_path, index=False)
        
        print(LogStyle.LINE + "="*110 + LogStyle.RESET)
        print(LogStyle.BOLD + " TRANS-SUITE EXPERIMENTAL EVALUATION SUMMARY METRICS" + LogStyle.RESET)
        print(LogStyle.LINE + "-"*110 + LogStyle.RESET)
        print(summary_df.to_string(index=False))
        print(LogStyle.LINE + "="*110 + LogStyle.RESET)
        LogStyle.log_success(f"Experimental evaluation metrics archived successfully to: '{csv_out_path}'")

    def plot_master_cdf(self, target_mode, target_rate):
        LogStyle.log_stage(f"Synthesizing Jitter/CDF Master Plots: Mode {target_mode} @ {target_rate}%")
        
        df_b   = self._resolve_dataframe('unpatched', 'qos_attack_0.0_mode0.csv') or self._resolve_dataframe('unpatched', 'qos_baseline.csv')
        df_un  = self._resolve_dataframe('unpatched', f'qos_attack_{target_rate}_mode{target_mode}.csv')
        df_unf = self._resolve_dataframe('unpatched', f'qos_attack_{target_rate}_mode{target_mode}_filtered.csv')
        df_p   = self._resolve_dataframe('patched',   f'qos_attack_{target_rate}_mode{target_mode}.csv')
        df_pf  = self._resolve_dataframe('patched',   f'qos_attack_{target_rate}_mode{target_mode}_filtered.csv')

        series_map = [
            ("Baseline",          df_b,   '#2ca02c', '-',  1),
            ("Unpatched Native",   df_un,  '#d62728', '-',  2),
            ("Unpatched Filtered", df_unf, '#ff7f0e', ':',  3),
            ("Patched Native",     df_p,   '#9467bd', '--', 4),
            ("Patched Filtered",   df_pf,  '#1f77b4', '-.', 5),
        ]

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
        WINDOW_LIMIT = 500

        # Subplot 1: Jitter Time Series
        for label, df, color, ls, z in series_map:
            if df is not None and not df.empty:
                ax1.plot(df['packet_id'][:WINDOW_LIMIT], df['latency_ms'][:WINDOW_LIMIT],
                         label=label, color=color, linestyle=ls, linewidth=1.5, alpha=0.8, zorder=z)

        ax1.set_ylim(0, 0.45)
        ax1.set_xlabel('Packet ID (Post Warm-up)')
        ax1.set_ylabel('Processing Latency (ms)')
        ax1.set_title(f'Latency Jitter Distribution (Mode {target_mode} @ {target_rate}%)')
        ax1.grid(True, linestyle=':', alpha=0.7)
        ax1.legend(loc='upper right', fontsize=10)

        # Subplot 2: Cumulative Distribution Metrics
        for label, df, color, ls, z in series_map:
            if df is not None and not df.empty:
                sorted_lat = np.sort(df['latency_ms'])
                probabilities = np.arange(len(sorted_lat)) / float(len(sorted_lat) - 1)
                ax2.plot(sorted_lat, probabilities, label=label, color=color, linestyle=ls, linewidth=1.5, alpha=0.9, zorder=z)

        ax2.axhline(y=0.99, color='black', linestyle='-', alpha=0.2, linewidth=1.0)
        
        for idx, (label, df, color, ls, z) in enumerate(series_map):
            if df is not None and not df.empty:
                p99 = df['latency_ms'].quantile(0.99)
                ax2.plot([p99, p99], [0, 0.99], color=color, linestyle=ls, linewidth=1.2, alpha=0.7)
                ax2.text(p99 * 1.05, 0.15 + idx * 0.12, f'{p99:.3f} ms', color=color, fontsize=10)

        ax2.set_xscale('log')
        ax2.set_xlim(1e-4, 10.0)
        ax2.set_xlabel('Processing Latency (ms) [Log Scale]')
        ax2.set_ylabel('CDF Probability')
        ax2.set_title('CDF Profiles with 99th Percentile Reference Lines')
        ax2.grid(True, which="both", linestyle=':', alpha=0.7)
        ax2.legend(loc='lower right', fontsize=10)

        self.export_figure(fig, "qos/master", f"comparison_mode{target_mode}_{target_rate}pct")
        plt.close(fig)

    def plot_pulse_timeline(self):
        LogStyle.log_stage("Generating Pulse Attack Mitigation Timeline (Mode 1)...")
        df_native = self._resolve_dataframe('unpatched', 'qos_attack_10.0_mode1.csv')
        df_filter = self._resolve_dataframe('unpatched', 'qos_attack_10.0_mode1_filtered.csv')

        if df_native is None or df_filter is None:
            LogStyle.log_warn("Aborting Pulse Timeline: Missing required mode1 target execution matrix dependencies.")
            return

        max_id = max(df_native['packet_id'].max(), df_filter['packet_id'].max())
        start_attack, end_attack = int(max_id * 0.30), int(max_id * 0.50)
        window_start, window_end = int(max_id * 0.25), int(max_id * 0.60)

        df_nat_zoom = df_native[df_native['packet_id'].between(window_start, window_end)]
        df_fil_zoom = df_filter[df_filter['packet_id'].between(window_start, window_end)]

        fig, ax = plt.subplots(figsize=(14, 6))
        ax.plot(df_nat_zoom['packet_id'], df_nat_zoom['latency_ms'], 
                label='Unpatched Native (No Defense)', color='#d62728', linewidth=1.0, alpha=0.5)
        ax.plot(df_fil_zoom['packet_id'], df_fil_zoom['latency_ms'], 
                label='Proposed FSM Filter', color='#1f77b4', linewidth=1.2, alpha=0.9)

        ax.axvspan(start_attack, end_attack, color='gray', alpha=0.2, label='Pulse Attack Window')
        ax.set_ylim(0, 0.45) 
        ax.set_xlim(window_start, window_end)
        ax.set_xlabel('Packet ID (Chronological Order)')
        ax.set_ylabel('Processing Latency (ms)')
        ax.set_title('Dynamic Resilience: System Recovery Under Pulse Attack')
        ax.grid(True, linestyle=':', alpha=0.7)
        ax.legend(loc='upper right')

        self.export_figure(fig, "qos/timeline", "pulse_recovery_timeline")
        plt.close(fig)

    def plot_periodic_timeline(self):
        LogStyle.log_stage("Generating Periodic Flapping Resilience Timeline (Mode 2)...")
        df_native = self._resolve_dataframe('unpatched', 'qos_attack_10.0_mode2.csv')
        df_filter = self._resolve_dataframe('unpatched', 'qos_attack_10.0_mode2_filtered.csv')

        if df_native is None or df_filter is None:
            LogStyle.log_warn("Aborting Periodic Timeline: Missing required mode2 target execution matrix dependencies.")
            return

        ROLLING_WINDOW = 500
        df_native['smoothed_latency'] = df_native['latency_ms'].rolling(window=ROLLING_WINDOW, min_periods=1).mean()
        df_filter['smoothed_latency'] = df_filter['latency_ms'].rolling(window=ROLLING_WINDOW, min_periods=1).mean()

        fig, ax = plt.subplots(figsize=(14, 6))
        ax.plot(df_filter['packet_id'], df_filter['latency_ms'], color='#1f77b4', linewidth=0.5, alpha=0.1, zorder=1)
        ax.plot(df_native['packet_id'], df_native['latency_ms'], color='#d62728', linewidth=0.5, alpha=0.1, zorder=2)

        ax.plot(df_filter['packet_id'], df_filter['smoothed_latency'], 
                label='Proposed FSM Filter (Smoothed)', color='#1f77b4', linewidth=1.5, alpha=0.9, zorder=3)
        ax.plot(df_native['packet_id'], df_native['smoothed_latency'], 
                label='Unpatched Native (Smoothed)', color='#d62728', linewidth=1.5, alpha=0.9, zorder=4)

        total_packet_indices = 1000000
        stride_len = total_packet_indices // 10
        legend_appended = False
        
        for iteration in range(10):
            if iteration % 2 == 1:
                lower_bound = iteration * stride_len
                upper_bound = (iteration + 1) * stride_len
                if not legend_appended:
                    ax.axvspan(lower_bound, upper_bound, color='gray', alpha=0.2, label='Attack Active Window')
                    legend_appended = True
                else:
                    ax.axvspan(lower_bound, upper_bound, color='gray', alpha=0.2)

        ax.set_ylim(0, 0.45) 
        ax.set_xlim(0, total_packet_indices)
        ax.set_xlabel('Packet ID (Chronological Order)')
        ax.set_ylabel('Processing Latency (ms)')
        ax.set_title('State Flapping Resilience: System Stability Under Periodic Attacks')
        ax.grid(True, linestyle=':', alpha=0.7)
        ax.legend(loc='upper right')

        self.export_figure(fig, "qos/timeline", "periodic_recovery_timeline")
        plt.close(fig)

    def print_diagnostic_debug(self):
        LogStyle.log_stage("Running Diagnostic State Validation Logs (Debug Module Pass)...")
        df_native = self._resolve_dataframe('unpatched', 'qos_attack_10.0_mode1.csv')
        df_filter = self._resolve_dataframe('unpatched', 'qos_attack_10.0_mode1_filtered.csv')

        if df_native is None or df_filter is None:
            LogStyle.log_error("Diagnostic suite execution terminated: Missing reference profile frameworks.")
            return

        max_id = max(df_native['packet_id'].max(), df_filter['packet_id'].max())
        atk_s, atk_e = int(max_id * 0.30), int(max_id * 0.50)

        nat_atk  = df_native[(df_native['packet_id'].between(atk_s, atk_e)) & (df_native['is_malware'] == 0)]
        filt_atk = df_filter[(df_filter['packet_id'].between(atk_s, atk_e)) & (df_filter['was_dropped'] == 0)]
        nat_pre  = df_native[(df_native['packet_id'] < atk_s) & (df_native['is_malware'] == 0)]
        filt_pre = df_filter[(df_filter['packet_id'] < atk_s) & (df_filter['was_dropped'] == 0)]

        dropped = df_filter[(df_filter['packet_id'].between(atk_s, atk_e)) & (df_filter['was_dropped'] == 1)]
        total_in_atk = len(df_filter[df_filter['packet_id'].between(atk_s, atk_e)])
        
        fp = df_filter[(df_filter['is_malware'] == 0) & (df_filter['was_dropped'] == 1)]
        total_safe = len(df_filter[df_filter['is_malware'] == 0])

        print(LogStyle.LINE + "\n" + "="*60 + LogStyle.RESET)
        print(LogStyle.BOLD + " DYNAMIC BOUNDARY AUDIT REPORT" + LogStyle.RESET)
        print(LogStyle.LINE + "-"*60 + LogStyle.RESET)
        print(" [PRE-ATTACK LIFECYCLE QUANTILES]")
        print(f"  Native Parser -> Median: {nat_pre['latency_ms'].median():.4f} ms | P99: {nat_pre['latency_ms'].quantile(0.99):.4f} ms")
        print(f"  FSM Pre-Filter -> Median: {filt_pre['latency_ms'].median():.4f} ms | P99: {filt_pre['latency_ms'].quantile(0.99):.4f} ms")
        print(" [ACTIVE ATTACK INTERCEPT PHASE (Benign Verification Subsamples)]")
        print(f"  Native Parser -> Median: {nat_atk['latency_ms'].median():.4f} ms | P99: {nat_atk['latency_ms'].quantile(0.99):.4f} ms (n={len(nat_atk)})")
        print(f"  FSM Pre-Filter -> Median: {filt_atk['latency_ms'].median():.4f} ms | P99: {filt_atk['latency_ms'].quantile(0.99):.4f} ms (n={len(filt_atk)})")
        print(" [DISCARD RATIO AND CLASSIFIER ACCURACY PERFORMANCE]")
        print(f"  Dropped Volumetric Ingress: {len(dropped)} / {total_in_atk} -> Effective Drop Rate: {100*len(dropped)/total_in_atk:.1f}%")
        print(f"  Benign Packets Misclassified: {len(fp)} / {total_safe} -> Empirical Matrix FPR: {100*len(fp)/total_safe:.2f}%")
        print(LogStyle.LINE + "="*60 + "\n" + LogStyle.RESET)

    def plot_budget_vs_attack(self, target_mode, target_rate):
        """
        Plots the attack distribution curve vs risk budget curve.
        """
        LogStyle.log_stage(f"Generating Budget vs Attack Intensity Curve: Mode {target_mode} @ {target_rate}%")
        
        # 1. Try to load the structured manual FSM trace first
        trace_filename = f"fsm_trace_rate_{float(target_rate):.1f}_mode{target_mode}.csv"
        target_path = os.path.join(self.root_output_dir, "traces", "unpatched", trace_filename)
        
        # 2. Fallback to training trace path if manual trace doesn't exist
        if not os.path.exists(target_path):
            training_filename = f"training_trace_{float(target_rate):.1f}_mode{target_mode}.csv"
            target_path = os.path.join(self.root_output_dir, "rl_env", training_filename)
        
        if not os.path.exists(target_path):
            LogStyle.log_error(f"Required trace file does not exist (checked both traces/ and rl_env/): '{target_path}'")
            return
            
        df = self._load_csv_file(target_path)
        if df is None or df.empty:
            LogStyle.log_error(f"Trace file is empty: '{target_path}'")
            return
            
        if 'max_sum_sq' not in df.columns or 'current_budget' not in df.columns:
            LogStyle.log_error(f"Trace file is missing required columns in '{target_path}'")
            return

        # Smooth using rolling average (1000 packets window)
        window = 1000
        df['smoothed_max_sum_sq'] = df['max_sum_sq'].rolling(window=window, min_periods=1).mean()
        df['smoothed_budget'] = df['current_budget'].rolling(window=window, min_periods=1).mean()

        # Downsample to speed up rendering
        plot_df = df.iloc[::100].reset_index(drop=True)

        fig, ax1 = plt.subplots(figsize=(12, 6))

        # Left Axis: Attack Intensity (F2 Sketch Square Sum)
        color = '#d62728'
        ax1.set_xlabel('Packet Index')
        ax1.set_ylabel('Attack Intensity (Smoothed F2 Sum Sq)', color=color)
        line1 = ax1.plot(plot_df.index * 100, plot_df['smoothed_max_sum_sq'], color=color, label='Attack Intensity', alpha=0.8)
        ax1.tick_params(axis='y', labelcolor=color)
        ax1.grid(True, linestyle=':', alpha=0.6)

        # Right Axis: FSM Virtual CPU Budget
        ax2 = ax1.twinx()
        color = '#1f77b4'
        ax2.set_ylabel('Virtual CPU Risk Budget (0-100)', color=color)
        line2 = ax2.plot(plot_df.index * 100, plot_df['smoothed_budget'], color=color, label='Risk Budget', alpha=0.8, linestyle='--')
        ax2.tick_params(axis='y', labelcolor=color)

        # Combine legend
        lines = line1 + line2
        labels = [l.get_label() for l in lines]
        ax1.legend(lines, labels, loc='upper right')

        plt.title(f'Attack Distribution vs Risk Budget Curve (Mode {target_mode} @ {target_rate}%)')

        self.export_figure(fig, "qos/budget", f"budget_vs_attack_mode{target_mode}_{target_rate}pct")
        plt.close(fig)
        LogStyle.log_success(f"Budget curve generated successfully.")