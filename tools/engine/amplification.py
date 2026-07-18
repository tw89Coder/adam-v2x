# engine/amplification.py
import os
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from engine.base import BasePlotter
from engine.logger import LogStyle

class AmplificationPlotter(BasePlotter):
    """
    Analyzes protocol parse latency complexities, computes linear regression fit metrics,
    and formats LaTeX tables representing MTU amplification profile statistics.
    """
    def __init__(self, root_output_dir="outputs"):
        super().__init__(root_output_dir)
        self.unpatched_path = os.path.join(root_output_dir, "csv_raw", "unpatched", "amplification_profile.csv")
        self.patched_path = os.path.join(root_output_dir, "csv_raw", "patched", "amplification_profile.csv")
        self.unified_path = os.path.join(root_output_dir, "csv_raw", "amplification_profile.csv")

    def execute(self):
        LogStyle.log_stage("Executing Amplification Profiling Pipeline...")
        
        df_merged = None

        # Validation Rule 1: Check for structured separate variant files
        if os.path.exists(self.unpatched_path) and os.path.exists(self.patched_path):
            LogStyle.log_info("Located structured independent variant amplification profiles.")
            df_un = self._load_csv_file(self.unpatched_path)
            df_pa = self._load_csv_file(self.patched_path)
            
            df_un = df_un.sort_values('total_size_bytes')
            df_pa = df_pa.sort_values('total_size_bytes')
            df_merged = pd.merge(df_un, df_pa, on='total_size_bytes', suffixes=('_un', '_pa'))
            
        # Validation Rule 2: Fallback to unified root compilation file
        elif os.path.exists(self.unified_path):
            LogStyle.log_info("Located unified root amplification profile compilation matrix.")
            df_merged = self._load_csv_file(self.unified_path)
            
            # Enforce strict column vector presence check to ensure data symmetry
            has_un = 'median_latency_ns_un' in df_merged.columns or 'median_latency_us_un' in df_merged.columns
            has_pa = 'median_latency_ns_pa' in df_merged.columns or 'median_latency_us_pa' in df_merged.columns
            
            if not (has_un and has_pa):
                LogStyle.log_error(
                    "Unified amplification matrix lacks distinct unpatched/patched data tracks.\n"
                    "          This confirms the patched experiment profile has not been executed yet,\n"
                    "          or its data was overwritten by a concurrent unpatched sweep node."
                )
                sys.exit(1)
        else:
            LogStyle.log_error(
                "Amplification profile dataset validation failed completely.\n"
                f"          Missing required variant pairs inside structured directories:\n"
                f"          -> '{self.unpatched_path}'\n"
                f"          -> '{self.patched_path}'"
            )
            sys.exit(1)

        # Standardize timing records to microsecond resolution
        for col in df_merged.columns:
            df_merged[col] = pd.to_numeric(df_merged[col], errors='coerce')
        df_merged = df_merged.dropna().reset_index(drop=True)
        
        # Deduplicate and aggregate multiple runs to eliminate line overlap issues
        df_merged = df_merged.groupby('total_size_bytes', as_index=False).mean()

        if 'median_latency_ns_un' in df_merged.columns:
            df_merged['median_latency_us_un'] = df_merged['median_latency_ns_un'] / 1000.0
            df_merged['median_latency_us_pa'] = df_merged['median_latency_ns_pa'] / 1000.0
        else:
            # Safe mapping when using custom merged data frames containing raw ns columns
            if 'median_latency_ns_un' not in df_merged.columns and 'median_latency_us_un' not in df_merged.columns:
                df_merged['median_latency_us_un'] = df_merged['median_latency_ns'] / 1000.0
                df_merged['median_latency_us_pa'] = df_merged['median_latency_ns'] / 1000.0

        df_merged['mitigation_gain'] = df_merged['median_latency_us_un'] / df_merged['median_latency_us_pa']

        COLOR_UNPATCHED = '#c44e52' # Seaborn soft red
        COLOR_PATCHED = '#4c72b0'   # Seaborn soft blue
        COLOR_GAIN = '#55a868'      # Seaborn soft green
        comma_formatter = ticker.StrMethodFormatter('{x:,.0f}')

        # Combined Plot: Absolute Latency & Mitigation Gain (Dual Y-Axis)
        fig, ax1 = plt.subplots(figsize=(6, 4.2))
        
        # Left Y-Axis: Latency (Unpatched vs Patched)
        ln1 = ax1.plot(df_merged['total_size_bytes'], df_merged['median_latency_us_un'], 
                       marker='o', linestyle='-', color=COLOR_UNPATCHED, label='Unpatched Latency')
        ln2 = ax1.plot(df_merged['total_size_bytes'], df_merged['median_latency_us_pa'], 
                       marker='o', linestyle='--', color=COLOR_PATCHED, label='Patched Latency')
        ax1.set_xlabel('Packet Size (Bytes)')
        ax1.set_ylabel('Median Parse Latency ($\mu$s)', color='black')
        ax1.tick_params(axis='y', labelcolor='black')
        ax1.xaxis.set_major_formatter(comma_formatter)
        ax1.grid(True, linestyle=':', alpha=0.6)
        
        # Add a secondary top X-axis representing the corresponding recursion depth
        # Since S_syn = 2 bytes, Depth = Size / 2.0
        ax_top = ax1.secondary_xaxis('top', functions=(lambda x: x / 2.0, lambda x: x * 2.0))
        ax_top.set_xlabel('Exploit Recursion Depth ($D$)', fontsize=11, labelpad=6)
        ax_top.tick_params(axis='x', labelsize=9.5)
        
        # Right Y-Axis: Performance Gain Ratio
        ax2 = ax1.twinx()
        ax2.spines['right'].set_visible(True)  # Re-enable the twin spine that was globally despined
        ln3 = ax2.plot(df_merged['total_size_bytes'], df_merged['mitigation_gain'], 
                       marker='D', linestyle='-.', color=COLOR_GAIN, label='Mitigation Gain')
        ax2.set_ylabel('Gain Ratio (Unpatched / Patched)', color=COLOR_GAIN)
        ax2.tick_params(axis='y', labelcolor=COLOR_GAIN)
        
        # Consolidate legends from both axes (position adjusted to not block lines)
        lns = ln1 + ln2 + ln3
        labs = [l.get_label() for l in lns]
        ax1.legend(lns, labs, loc='upper left')
        plt.tight_layout()
        
        # Export the combined figure
        self.export_figure(fig, "amplification", "parse_latency_and_gain")
        plt.close(fig)

        # Algorithmic Complexity Modeling Execution
        x = df_merged['total_size_bytes'].values
        y = df_merged['median_latency_us_un'].values
        coefficients = np.polyfit(x, y, 1)
        slope, intercept = coefficients[0], coefficients[1]
        
        y_pred = np.poly1d(coefficients)(x)
        r_squared = 1 - (np.sum((y - y_pred)**2) / np.sum((y - np.mean(y))**2))

        print(LogStyle.LINE + "="*80 + LogStyle.RESET)
        print(LogStyle.BOLD + " MATHEMATICAL COMPLEXITY VERIFICATION PROOF" + LogStyle.RESET)
        print(LogStyle.LINE + "-"*80 + LogStyle.RESET)
        print(f" Hypothesis: Unbounded parsing linear regression matches stable O(N) profile.")
        print(f" Fit Equation:     y = {slope:.4f}x + ({intercept:.4f})")
        print(f" Target Slope (m): {slope:.4f} us per payload byte")
        print(f" R-squared (R2):   {r_squared:.6f}")
        if r_squared > 0.99:
            LogStyle.log_success(f"Mathematical O(N) linear growth verified successfully (R2 = {r_squared:.4f}).")
        else:
            LogStyle.log_warn("Observed regression distribution diverges from standard linear complexity model boundaries.")
        print(LogStyle.LINE + "="*80 + LogStyle.RESET)

        self._generate_latex_table(df_merged)

    def _generate_latex_table(self, df_merged):
        target_sizes = [353, 687, 1007, 1400]
        df_table = df_merged[df_merged['total_size_bytes'].isin(target_sizes)].copy()
        
        self._ensure_directory_exists(self.stats_dir)
        tex_path = os.path.join(self.stats_dir, "amplification_table.tex")
        
        latex_str = (
            "\\begin{table}[htbp]\n"
            "\\centering\n"
            "\\caption{Performance Profiling of MTU-Constrained Amplification}\n"
            "\\label{tab:amp_profiling}\n"
            "\\begin{tabular}{@{}l l r r r r@{}}\n"
            "\\toprule\n"
            "\\textbf{Packet Size} & \\textbf{Flood Region} & \\textbf{Unpatched (us)} & "
            "\\textbf{Patched (us)} & \\textbf{Gain Ratio} & \\textbf{Amp Factor} \\\\ \\midrule\n"
        )

        for _, row in df_table.iterrows():
            pkt_size = int(row['total_size_bytes'])
            flood_size = int(row.get('flood_size_bytes_un', 0)) if 'flood_size_bytes_un' in row else 0
            un_us = row['median_latency_us_un']
            pa_us = row.get('median_latency_us_pa', un_us)
            gain = row.get('mitigation_gain', 1.0)
            amp = row.get('amp_vs_normal_un', 1.0)
            
            tex_label = f"\\textbf{{{pkt_size} B}} (PoC)" if pkt_size == 353 else (f"\\textbf{{{pkt_size} B}} (MTU)" if pkt_size == 1400 else f"{pkt_size} B")
            latex_str += f"{tex_label} & {flood_size} B & {un_us:.2f} & {pa_us:.2f} & {gain:.1f}$\\times$ & {amp:.2f}$\\times$ \\\\\n"

        latex_str += "\\bottomrule\n\\end{tabular}\n\\end{table}\n"
        
        with open(tex_path, "w", encoding="utf-8") as f:
            f.write(latex_str)
        LogStyle.log_success(f"Structured LaTeX table script written to: '{tex_path}'")