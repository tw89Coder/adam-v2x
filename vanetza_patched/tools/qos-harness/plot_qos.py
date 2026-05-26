import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os
import glob  # NEW: For using the '*' wildcard

def load_data(file_pattern, warmup=50, jitter_threshold_ms=5.0):
    filepath_pattern = os.path.join('csv_data', file_pattern)
    matched_files = glob.glob(filepath_pattern)
    
    # If we are looking for the Native file, ensure we don't accidentally grab the 'filtered' file
    if "filtered" not in file_pattern:
        matched_files = [f for f in matched_files if "filtered" not in f]
        
    if not matched_files:
        return None
        
    # If you ran multiple modes previously, automatically grab the newest one!
    latest_file = max(matched_files, key=os.path.getmtime)
    print(f"[Read] Loading {latest_file}...")
    
    df = pd.read_csv(latest_file)
    df['latency_ms'] = df['latency_ns'] / 1e6

    # Remove warmup samples
    df = df.iloc[warmup:].reset_index(drop=True)

    # Filter OS Jitter: threshold far above real attack peak (~1.5ms)
    before = len(df)
    df = df[df['latency_ms'] < jitter_threshold_ms].reset_index(drop=True)
    after = len(df)
    if before != after:
        print(f"  [Jitter] Removed {before - after} OS outliers (>{jitter_threshold_ms}ms) from {latest_file}")

    return df

def plot_cdf(ax, data, label, color, linestyle, linewidth, zorder):
    if data is None or len(data) == 0: return
    sorted_data = np.sort(data)
    yvals = np.arange(len(sorted_data)) / float(len(sorted_data) - 1)
    ax.plot(sorted_data, yvals, label=label, color=color, linestyle=linestyle, linewidth=linewidth, alpha=0.9, zorder=zorder)

def plot_scenario(fig_name, title_prefix, df_base, data_dict, rates, styles):
    window_size = 500  
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))

    # ==========================================
    # Left Graph: Time Series
    # ==========================================
    if df_base is not None and not df_base.empty:
        ax1.plot(df_base['packet_id'][:window_size], df_base['latency_ms'][:window_size], 
                 label='Baseline', color='#2ca02c', linestyle='-', linewidth=1.5, alpha=0.5, zorder=1)
        
        p99_base = df_base['latency_ms'].quantile(0.99)
        ax1.axhline(y=p99_base, color='gray', linestyle='-.', alpha=0.7, linewidth=1.0)
        ax1.text(0, p99_base + 0.01, f' Baseline P99: {p99_base:.3f} ms', color='gray', fontsize=10)

    z = 2
    for r in rates:
        if data_dict[r] is not None and not data_dict[r].empty:
            ax1.plot(data_dict[r].index[:window_size], data_dict[r]['latency_ms'][:window_size], 
                     label=f'Attack ({r}%)', color=styles[r]['color'], linestyle=styles[r]['ls'], 
                     linewidth=styles[r]['lw'], alpha=0.9, zorder=z)
            z += 1

    ax1.set_ylim(0, 0.45)
    ax1.set_xlabel('Packet ID (Post Warm-up)')
    ax1.set_ylabel('Processing Latency (ms)')
    ax1.set_title(f'{title_prefix} - Latency Jitter')
    ax1.grid(True, linestyle=':', alpha=0.7)
    ax1.legend(loc='upper right')

    # ==========================================
    # Right Graph: CDF with 99th Percentile
    # ==========================================
    if df_base is not None and not df_base.empty:
        plot_cdf(ax2, df_base['latency_ms'], 'Baseline', '#2ca02c', '-', 1.5, 1)
        
    z = 2
    for r in rates:
        if data_dict[r] is not None and not data_dict[r].empty:
            plot_cdf(ax2, data_dict[r]['latency_ms'], f'Attack ({r}%)', styles[r]['color'], styles[r]['ls'], styles[r]['lw'], z)
            z += 1

    ax2.axhline(y=0.99, color='black', linestyle='-', alpha=0.2, linewidth=1.0)

    if df_base is not None and not df_base.empty:
        ax2.plot([p99_base, p99_base], [0, 0.99], color='#2ca02c', linestyle='-', linewidth=1.2, alpha=0.8)
        ax2.text(p99_base * 1.05, 0.85, f'{p99_base:.3f} ms', color='#2ca02c', fontsize=10)

    y_text_offset = 0.75
    for r in rates:
        if data_dict[r] is not None and not data_dict[r].empty:
            p99_val = data_dict[r]['latency_ms'].quantile(0.99)
            color = styles[r]['color']
            ls = styles[r]['ls']
            ax2.plot([p99_val, p99_val], [0, 0.99], color=color, linestyle=ls, linewidth=1.2, alpha=0.8)
            ax2.text(p99_val * 1.05, y_text_offset, f'{p99_val:.3f} ms', color=color, fontsize=10)
            y_text_offset -= 0.10

    ax2.set_xscale('log')
    ax2.set_xlim(1e-4, 10.0)
    ax2.set_xlabel('Processing Latency (ms) [Log Scale]')
    ax2.set_ylabel('CDF Probability')
    ax2.set_title(f'{title_prefix} - CDF (99th Drop-lines)')
    ax2.grid(True, which="both", linestyle=':', alpha=0.7)
    ax2.legend(loc='lower right')
    
    plt.tight_layout()
    plt.savefig(f'result/{fig_name}.png', dpi=300, bbox_inches='tight')
    plt.savefig(f'result/{fig_name}.pdf', format='pdf', bbox_inches='tight')
    plt.close()

def main():
    os.makedirs('result', exist_ok=True)
    env_name = "Patched" if "vanetza_patched" in os.getcwd() else "Unpatched"
    
    df_base = load_data('qos_baseline.csv')
    rates = ['1.0', '5.0', '10.0']
    
    print("\n[*] Loading Data Files...")
    # ==========================================
    # NEW: Using the '*' wildcard! Python will find Mode 0, Mode 1, etc.
    # ==========================================
    native_data = {r: load_data(f'qos_attack_{r}_mode0.csv') for r in rates}
    filter_data_raw = {r: load_data(f'qos_attack_{r}_mode0_filtered.csv') for r in rates}
    
    filter_data_admitted = {}
    security_metrics = {}
    
    for r in rates:
        if filter_data_raw[r] is not None and not filter_data_raw[r].empty:
            df = filter_data_raw[r]
            if 'was_dropped' in df.columns and 'is_malware' in df.columns:
                filter_data_admitted[r] = df[df['was_dropped'] == 0].reset_index(drop=True)
                
                tp = len(df[(df['is_malware'] == 1) & (df['was_dropped'] == 1)])
                fp = len(df[(df['is_malware'] == 0) & (df['was_dropped'] == 1)])
                tn = len(df[(df['is_malware'] == 0) & (df['was_dropped'] == 0)])
                fn = len(df[(df['is_malware'] == 1) & (df['was_dropped'] == 0)])
                
                fpr = (fp / (fp + tn)) * 100.0 if (fp + tn) > 0 else 0.0
                fnr = (fn / (fn + tp)) * 100.0 if (fn + tp) > 0 else 0.0
                
                security_metrics[r] = {"FPR (%)": round(fpr, 4), "FNR (%)": round(fnr, 4)}
            else:
                filter_data_admitted[r] = df
                security_metrics[r] = {"FPR (%)": "N/A", "FNR (%)": "N/A"}
        else:
            filter_data_admitted[r] = None
            security_metrics[r] = {"FPR (%)": "N/A", "FNR (%)": "N/A"}

    stats_list = []
    
    def add_stat_row(scenario, df, fpr="N/A", fnr="N/A"):
        stats_list.append({
            "Scenario": scenario, 
            "Mean_ms": round(df['latency_ms'].mean(), 4), 
            "Median_ms": round(df['latency_ms'].median(), 4), 
            "P99_ms": round(df['latency_ms'].quantile(0.99), 4), 
            "Max_ms": round(df['latency_ms'].max(), 4),
            "FPR (%)": fpr,
            "FNR (%)": fnr
        })

    if df_base is not None and not df_base.empty:
        add_stat_row("Baseline (Optimal)", df_base)
        
    for r in rates:
        if native_data[r] is not None and not native_data[r].empty:
            add_stat_row(f"Native Parser ({r}%)", native_data[r])
    
    for r in rates:
        if filter_data_admitted[r] is not None and not filter_data_admitted[r].empty:
            fpr_val = security_metrics[r]["FPR (%)"]
            fnr_val = security_metrics[r]["FNR (%)"]
            add_stat_row(f"Filter Admitted ({r}%)", filter_data_admitted[r], fpr=fpr_val, fnr=fnr_val)
            
            if 'was_dropped' in filter_data_raw[r].columns:
                df_dropped = filter_data_raw[r][filter_data_raw[r]['was_dropped'] == 1].reset_index(drop=True)
                if not df_dropped.empty:
                    add_stat_row(f"  -> Blocked CPU Cost", df_dropped)

    if len(stats_list) > 0:
        stats_df = pd.DataFrame(stats_list)
        csv_filename = f'result/local_qos_statistics_{env_name}.csv'
        stats_df.to_csv(csv_filename, index=False)
        
        print("\n" + "="*95)
        print(f" 📊 Local QoS & Security Evaluation Table ({env_name} Environment)")
        print("="*95)
        print(stats_df.to_string(index=False))
        print("="*95 + "\n")
    else:
        print("No valid CSV data found to print table.")

    plt.rcParams.update({'font.size': 12, 'axes.labelsize': 14, 'axes.titlesize': 14, 'font.family': 'serif'})
    
    styles = {
        '1.0': {'color': '#1f77b4', 'ls': '--', 'lw': 1.5},
        '5.0': {'color': '#ff7f0e', 'ls': '-.', 'lw': 1.5},
        '10.0': {'color': '#d62728', 'ls': '-', 'lw': 1.5}
    }

    plot_scenario(f'local_{env_name}_Native_Scaling', f'[{env_name}] Native Parser', df_base, native_data, rates, styles)
    plot_scenario(f'local_{env_name}_Filter_Scaling', f'[{env_name}] Proposed Pre-filter', df_base, filter_data_raw, rates, styles)
    
    print(f"[+] Local plots (PNG & PDF) and statistics CSV for {env_name} generated successfully!")

if __name__ == "__main__":
    main()