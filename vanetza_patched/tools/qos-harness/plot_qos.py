import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os

def load_data(filename, warmup=50):
    filepath = os.path.join('csv_data', filename)
    if not os.path.exists(filepath):
        return None
    df = pd.read_csv(filepath)
    df['latency_ms'] = df['latency_ns'] / 1e6
    return df.iloc[warmup:].reset_index(drop=True)

def plot_cdf(ax, data, label, color, linestyle, linewidth, zorder):
    if data is None: return
    sorted_data = np.sort(data)
    yvals = np.arange(len(sorted_data)) / float(len(sorted_data) - 1)
    ax.plot(sorted_data, yvals, label=label, color=color, linestyle=linestyle, linewidth=linewidth, alpha=0.9, zorder=zorder)

def plot_scenario(fig_name, title_prefix, df_base, data_dict, rates, styles):
    window_size = 500  
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))

    # ==========================================
    # 左圖: Time Series
    # ==========================================
    ax1.plot(df_base['packet_id'][:window_size], df_base['latency_ms'][:window_size], 
             label='Baseline', color='#2ca02c', linestyle='-', linewidth=1.5, alpha=0.5, zorder=1)
    
    # 畫一條 Baseline P99 的水平輔助線
    if df_base is not None:
        p99_base = df_base['latency_ms'].quantile(0.99)
        ax1.axhline(y=p99_base, color='gray', linestyle='-.', alpha=0.7, linewidth=1.0)
        ax1.text(0, p99_base + 0.01, f' Baseline P99: {p99_base:.3f} ms', color='gray', fontsize=10)

    z = 2
    for r in rates:
        if data_dict[r] is not None:
            ax1.plot(data_dict[r]['packet_id'][:window_size], data_dict[r]['latency_ms'][:window_size], 
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
    # 右圖: CDF 與 99th Percentile 垂直下降線
    # ==========================================
    plot_cdf(ax2, df_base['latency_ms'], 'Baseline', '#2ca02c', '-', 1.5, 1)
    z = 2
    for r in rates:
        plot_cdf(ax2, data_dict[r]['latency_ms'], f'Attack ({r}%)', styles[r]['color'], styles[r]['ls'], styles[r]['lw'], z)
        z += 1

    # 繪製 Y=0.99 的基準水平線
    ax2.axhline(y=0.99, color='black', linestyle='-', alpha=0.2, linewidth=1.0)

    # 標註 Baseline 的 P99
    if df_base is not None:
        ax2.plot([p99_base, p99_base], [0, 0.99], color='#2ca02c', linestyle='-', linewidth=1.2, alpha=0.8)
        ax2.text(p99_base * 1.05, 0.85, f'{p99_base:.3f} ms', color='#2ca02c', fontsize=10)

    # 標註各攻擊比例的 P99，並錯開文字高度
    y_text_offset = 0.75
    for r in rates:
        if data_dict[r] is not None:
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
    
    native_data = {r: load_data(f'qos_attack_{r}_mode0.csv') for r in rates}
    filter_data = {r: load_data(f'qos_attack_{r}_mode0_filtered.csv') for r in rates}

    # ==========================================
    # 建立統計數據表格並匯出
    # ==========================================
    stats_list = []
    if df_base is not None:
        stats_list.append({"Scenario": "Baseline", "Mean_ms": round(df_base['latency_ms'].mean(), 4), "Median_ms": round(df_base['latency_ms'].median(), 4), "P99_ms": round(df_base['latency_ms'].quantile(0.99), 4), "P99.9_ms": round(df_base['latency_ms'].quantile(0.999), 4), "Max_ms": round(df_base['latency_ms'].max(), 4)})
        
    for r in rates:
        if native_data[r] is not None:
            df = native_data[r]
            stats_list.append({"Scenario": f"Native Parser ({r}%)", "Mean_ms": round(df['latency_ms'].mean(), 4), "Median_ms": round(df['latency_ms'].median(), 4), "P99_ms": round(df['latency_ms'].quantile(0.99), 4), "P99.9_ms": round(df['latency_ms'].quantile(0.999), 4), "Max_ms": round(df['latency_ms'].max(), 4)})
    
    for r in rates:
        if filter_data[r] is not None:
            df = filter_data[r]
            stats_list.append({"Scenario": f"Pre-filter ({r}%)", "Mean_ms": round(df['latency_ms'].mean(), 4), "Median_ms": round(df['latency_ms'].median(), 4), "P99_ms": round(df['latency_ms'].quantile(0.99), 4), "P99.9_ms": round(df['latency_ms'].quantile(0.999), 4), "Max_ms": round(df['latency_ms'].max(), 4)})

    stats_df = pd.DataFrame(stats_list)
    csv_filename = f'result/local_qos_statistics_{env_name}.csv'
    stats_df.to_csv(csv_filename, index=False)
    
    print("\n" + "="*80)
    print(f" 📊 Local QoS Evaluation Table ({env_name} Environment)")
    print("="*80)
    print(stats_df.to_string(index=False))
    print("="*80 + "\n")

    plt.rcParams.update({'font.size': 12, 'axes.labelsize': 14, 'axes.titlesize': 14, 'font.family': 'serif'})
    
    styles = {
        '1.0': {'color': '#1f77b4', 'ls': ':', 'lw': 1.5},
        '5.0': {'color': '#ff7f0e', 'ls': '-.', 'lw': 1.5},
        '10.0': {'color': '#d62728', 'ls': '-', 'lw': 1.5}
    }

    plot_scenario(f'local_{env_name}_Native_Scaling', f'[{env_name}] Native Parser', df_base, native_data, rates, styles)
    plot_scenario(f'local_{env_name}_Filter_Scaling', f'[{env_name}] Proposed Pre-filter', df_base, filter_data, rates, styles)
    
    print(f"[+] Local plots (PNG & PDF) and statistics CSV for {env_name} generated successfully!")

if __name__ == "__main__":
    main()