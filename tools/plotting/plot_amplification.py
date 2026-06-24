import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import os

# Configuration Paths
UNPATCHED_PATH = "vanetza_unpatched/tools/qos-harness/csv_data/amplification_profile.csv"
PATCHED_PATH = "vanetza_patched/tools/qos-harness/csv_data/amplification_profile.csv"
OUTPUT_DIR = "final_results"

def load_and_clean_csv(file_path):
    print(f"[*] Reading: {file_path}")
    try:
        df = pd.read_csv(file_path, comment='#')
        for col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
        df = df.dropna().reset_index(drop=True)
        if 'median_latency_ns' in df.columns:
            df['median_latency_us'] = df['median_latency_ns'] / 1000.0
        return df
    except Exception as e:
        print(f"[!] Error reading {file_path}: {e}")
        return None

def apply_top_tier_academic_style():
    plt.rcParams.update({
        'font.family': 'serif',
        'font.serif': ['Times New Roman', 'DejaVu Serif'],
        'font.size': 12,
        'axes.labelsize': 13,
        'axes.titlesize': 14,
        'axes.titleweight': 'bold',
        'axes.linewidth': 1.2,
        'legend.fontsize': 11,
        'legend.frameon': True,
        'legend.edgecolor': 'black',
        'legend.framealpha': 1.0,
        'xtick.labelsize': 11,
        'ytick.labelsize': 11,
        'xtick.direction': 'in',
        'ytick.direction': 'in',
        'xtick.major.size': 5,
        'ytick.major.size': 5,
        'axes.grid': True,
        'grid.alpha': 0.4,
        'grid.linestyle': ':',
        'lines.linewidth': 2.5,
        'lines.markersize': 8,
        'figure.dpi': 300,
        'savefig.bbox': 'tight',
        'savefig.pad_inches': 0.05
    })

def main():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    df_unpatched = load_and_clean_csv(UNPATCHED_PATH)
    df_patched = load_and_clean_csv(PATCHED_PATH)

    if df_unpatched is None or df_patched is None:
        print("[!] Failed to load CSV files. Aborting.")
        return

    df_unpatched = df_unpatched.sort_values('total_size_bytes')
    df_patched = df_patched.sort_values('total_size_bytes')
    df_merged = pd.merge(df_unpatched, df_patched, on='total_size_bytes', suffixes=('_un', '_pa'))

    apply_top_tier_academic_style()
    
    COLOR_UNPATCHED = '#A51C30' 
    COLOR_PATCHED = '#003366'   
    COLOR_GAIN = '#00665E'      
    
    comma_formatter = ticker.StrMethodFormatter('{x:,.0f}')

    # Plot 1: Absolute Parse Latency Comparison
    fig1, ax1 = plt.subplots(figsize=(6, 4.5))
    ax1.plot(df_unpatched['total_size_bytes'], df_unpatched['median_latency_us'], 
             marker='o', linestyle='-', color=COLOR_UNPATCHED, label='Unpatched')
    ax1.plot(df_patched['total_size_bytes'], df_patched['median_latency_us'], 
             marker='s', linestyle='--', color=COLOR_PATCHED, label='Patched (Mitigated)')
    
    ax1.set_xlabel('Packet Size (Bytes)')
    ax1.set_ylabel('Median Parse Latency (us)')
    ax1.set_title('Parse Latency vs. Packet Size')
    ax1.xaxis.set_major_formatter(comma_formatter)
    ax1.legend(loc='upper left')
    
    fig1_path = os.path.join(OUTPUT_DIR, 'parse_latency_comparison.png')
    plt.savefig(fig1_path)
    print(f"[*] Saved Plot: {fig1_path}")
    plt.close(fig1)

    # Plot 2: Performance Mitigation Gain
    df_merged['mitigation_gain'] = df_merged['median_latency_us_un'] / df_merged['median_latency_us_pa']
    
    fig2, ax2 = plt.subplots(figsize=(6, 4.5))
    ax2.plot(df_merged['total_size_bytes'], df_merged['mitigation_gain'], 
             marker='D', linestyle='-', color=COLOR_GAIN, label='Latency Reduction Gain')
    
    ax2.set_xlabel('Packet Size (Bytes)')
    ax2.set_ylabel('Gain Factor (Unpatched / Patched)')
    ax2.set_title('Performance Gain Post-Mitigation')
    ax2.xaxis.set_major_formatter(comma_formatter)
    ax2.legend(loc='upper left')
    
    fig2_path = os.path.join(OUTPUT_DIR, 'mitigation_performance_gain.png')
    plt.savefig(fig2_path)
    print(f"[*] Saved Plot: {fig2_path}")
    plt.close(fig2)

    # Mathematical Complexity Proof
    x = df_merged['total_size_bytes'].values
    y = df_merged['median_latency_us_un'].values

    coefficients = np.polyfit(x, y, 1)
    slope = coefficients[0]
    intercept = coefficients[1]
    
    p = np.poly1d(coefficients)
    y_pred = p(x)
    y_mean = np.mean(y)
    ss_tot = np.sum((y - y_mean)**2)
    ss_res = np.sum((y - y_pred)**2)
    r_squared = 1 - (ss_res / ss_tot)

    print("\n" + "="*80)
    print(" MATHEMATICAL COMPLEXITY PROOF (For Paper)")
    print("="*80)
    print("Hypothesis: Unbounded recursion exhibits stable O(N) linear growth.")
    print(f"Linear Equation:  y = {slope:.4f}x + ({intercept:.4f})")
    print(f"Slope (m):        {slope:.4f} us per byte of flood payload")
    print(f"R-squared (R2):   {r_squared:.6f}")
    print("\nConclusion:")
    if r_squared > 0.99:
        print(f"The R2 value of {r_squared:.4f} indicates a near-perfect linear relationship.")
        print("This proves the exploit is a highly stable, linear O(N) resource exhaustion attack.")
    else:
        print("The growth exhibits non-linear characteristics.")
    print("="*80 + "\n")
    
    # ---------------------------------------------------------
    # Terminal Data Table & LaTeX Generation (Pure ASCII)
    # ---------------------------------------------------------
    target_sizes = [353, 687, 1007, 1400]
    df_table = df_merged[df_merged['total_size_bytes'].isin(target_sizes)].copy()

    # ANSI Colors for Terminal
    C_RESET = "\033[0m"
    C_BOLD_WHITE = "\033[1;37m"
    C_RED = "\033[31m"
    C_CYAN = "\033[36m"
    C_BOLD_GREEN = "\033[1;32m"
    
    print("\n" + "="*85)
    print(" TERMINAL PREVIEW & LATEX GENERATOR")
    print("="*85)
    print(C_BOLD_WHITE + f"{'Packet Size':<15} | {'Flood (B)':<10} | {'Unpatched (us)':<15} | {'Patched (us)':<15} | {'Gain Ratio':<10} | {'Amp Factor'}" + C_RESET)
    print("-" * 85)
    
    latex_str = """\\begin{table}[htbp]
                    \\centering
                    \\caption{Performance Profiling of MTU-Constrained Amplification}
                    \\label{tab:amp_profiling}
                    \\begin{tabular}{@{}l l r r r r@{}}
                    \\toprule
                    \\textbf{Packet Size} & \\textbf{Flood Region} & \\textbf{Unpatched (us)} & \\textbf{Patched (us)} & \\textbf{Gain Ratio} & \\textbf{Amp Factor} \\\\ \\midrule
                """

    for _, row in df_table.iterrows():
        pkt_size = int(row['total_size_bytes'])
        flood_size = int(row['flood_size_bytes_un'])
        un_us = row['median_latency_us_un']
        pa_us = row['median_latency_us_pa']
        gain = row['mitigation_gain']
        amp = row['amp_vs_normal_un']
        
        # Labels for Terminal
        term_label = f"{pkt_size} B"
        if pkt_size == 353: term_label += " (PoC)"
        if pkt_size == 1400: term_label += " (MTU)"
        
        # Labels for LaTeX
        if pkt_size in [353, 1400]:
            tex_label = f"\\textbf{{{pkt_size} B}} " + ("(PoC)" if pkt_size == 353 else "(MTU)")
        else:
            tex_label = f"{pkt_size} B"
            
        # Print to Terminal with Colors
        print(f"{term_label:<15} | {str(flood_size)+' B':<10} | "
              f"{C_RED}{un_us:<15.2f}{C_RESET} | "
              f"{C_CYAN}{pa_us:<15.2f}{C_RESET} | "
              f"{C_BOLD_GREEN}{gain:>6.1f}x{C_RESET}    | "
              f"{amp:>6.2f}x")
              
        # Append to LaTeX (using normal us instead of micro symbol to avoid encoding issues)
        latex_str += f"{tex_label} & {flood_size} B & {un_us:.2f} & {pa_us:.2f} & {gain:.1f}$\\times$ & {amp:.2f}$\\times$ \\\\\n"

    latex_str += """\\bottomrule
                    \\end{tabular}
                    \\end{table}"""

    print("-" * 85 + "\n")
    print("[*] LaTeX Code for Paper:\n")
    print(latex_str)
    print("="*85 + "\n")

if __name__ == "__main__":
    main()