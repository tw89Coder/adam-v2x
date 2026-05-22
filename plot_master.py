import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os

def load_data(repo_name, filename, warmup=50):
    base_path = os.path.dirname(os.path.abspath(__file__))
    filepath = os.path.join(base_path, repo_name, 'tools', 'qos-harness', 'csv_data', filename)
    if not os.path.exists(filepath):
        print(f"[Warning] File not found: {filepath}")
        return None
    df = pd.read_csv(filepath)
    df['latency_ms'] = df['latency_ns'] / 1e6
    return df.iloc[warmup:].reset_index(drop=True)

def plot_cdf(ax, data, label, color, linestyle, linewidth, zorder):
    if data is None: return
    sorted_data = np.sort(data)
    yvals = np.arange(len(sorted_data)) / float(len(sorted_data) - 1)
    ax.plot(sorted_data, yvals, label=label, color=color, linestyle=linestyle, linewidth=linewidth, alpha=0.9, zorder=zorder)

def main():
    base_path = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(base_path, 'final_results')
    os.makedirs(output_dir, exist_ok=True)

    print("[*] Loading Mode 0 (Uniform Random) experimental data...")
    df_base = load_data('vanetza_unpatched', 'qos_attack_0.0_mode0.csv') # 注意：請確保你有跑 0.0% 當作 Baseline
    df_unpatched = load_data('vanetza_unpatched', 'qos_attack_10.0_mode0.csv')
    df_unpatched_filter = load_data('vanetza_unpatched', 'qos_attack_10.0_mode0_filtered.csv')
    df_patched = load_data('vanetza_patched', 'qos_attack_10.0_mode0.csv')
    df_patched_filter = load_data('vanetza_patched', 'qos_attack_10.0_mode0_filtered.csv')

    # 配置 5 條線的完全對比色彩與虛實樣式 (粗細統一為 1.5)
    datasets = [
        ("Baseline (No Attack)", df_base, '#2ca02c', '-', 1),                # 綠色實線
        ("Unpatched Native", df_unpatched, '#d62728', '-', 2),               # 紅色實線
        ("Unpatched + Pre-filter", df_unpatched_filter, '#ff7f0e', ':', 3),  # 橘色點線
        ("Official Patch Native", df_patched, '#9467bd', '--', 4),           # 紫色虛線
        ("Patched + Pre-filter (Hybrid)", df_patched_filter, '#1f77b4', '-.', 5) # 藍色點折線
    ]

    # ==========================================
    # 1. 輸出學術論文精確統計表格
    # ==========================================
    stats_list = []
    for name, df, _, _, _ in datasets:
        if df is not None:
            stats_list.append({
                "Scenario": name,
                "Mean_ms": round(df['latency_ms'].mean(), 4),
                "Median_ms": round(df['latency_ms'].median(), 4),
                "P99_ms": round(df['latency_ms'].quantile(0.99), 4),
                "P99.9_ms": round(df['latency_ms'].quantile(0.999), 4),
                "Max_ms": round(df['latency_ms'].max(), 4)
            })
    
    stats_df = pd.DataFrame(stats_list)
    stats_df.to_csv(os.path.join(output_dir, 'qos_statistics_table.csv'), index=False)
    
    print("\n" + "="*85)
    print(" 📊 QoS Multi-Dimensional Evaluation Table (Ready for Paper)")
    print("="*85)
    print(stats_df.to_string(index=False))
    print("="*85 + "\n")

    # ==========================================
    # 2. 繪製標準學術對照圖
    # ==========================================
    plt.rcParams.update({'font.size': 12, 'axes.labelsize': 14, 'axes.titlesize': 14, 'font.family': 'serif'})
    window_size = 500  
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))

    # ----- 左圖: Time Series -----
    for name, df, color, ls, z in datasets:
        if df is not None:
            ax1.plot(df['packet_id'][:window_size], df['latency_ms'][:window_size], 
                     label=name, color=color, linestyle=ls, linewidth=1.5, alpha=0.8 if z!=1 else 0.4, zorder=z)

    ax1.set_ylim(0, 0.45)
    ax1.set_xlabel('Packet ID (Post Warm-up)')
    ax1.set_ylabel('Processing Latency (ms)')
    ax1.set_title('Master Comparison: Latency Jitter')
    ax1.grid(True, linestyle=':', alpha=0.7)
    ax1.legend(loc='upper right', fontsize=10)

    # ----- 右圖: CDF -----
    for name, df, color, ls, z in datasets:
        if df is not None:
            plot_cdf(ax2, df['latency_ms'], name, color, ls, 1.5, z)

    # 繪製 Y=0.99 的基準水平線
    ax2.axhline(y=0.99, color='black', linestyle='-', alpha=0.2, linewidth=1.0)

    # 橫向錯開標籤的初始 X 軸位置，避免文字在 log scale 下重疊
    x_text_positions = [1.2e-2, 1.2e-1, 4.5e-2, 2.2e-2, 5.0e-3]
    text_idx = 0

    # 精確計算每條曲線的 P99，並繪製從曲線交點向下落到 X 軸的垂直虛線
    for name, df, color, ls, z in datasets:
        if df is not None:
            p99_val = df['latency_ms'].quantile(0.99)
            # 垂直線：從 Y=0 到 Y=0.99
            ax2.plot([p99_val, p99_val], [0, 0.99], color=color, linestyle=ls, linewidth=1.2, alpha=0.8)
            # 在 X 軸上方稍微錯開的高度標註精確數值
            ax2.text(p99_val * 1.05, 0.2 + (text_idx * 0.12), f'{p99_val:.3f} ms', color=color, fontsize=10)
            text_idx += 1

    ax2.set_xscale('log')
    ax2.set_xlim(1e-4, 10.0)
    ax2.set_xlabel('Processing Latency (ms) [Log Scale]')
    ax2.set_ylabel('CDF Probability')
    ax2.set_title('Master Comparison: CDF (99th Drop-lines)')
    ax2.grid(True, which="both", linestyle=':', alpha=0.7)
    ax2.legend(loc='lower right', fontsize=10)
    
    plt.tight_layout()
    fig.savefig(os.path.join(output_dir, 'master_defense_comparison.png'), dpi=300, bbox_inches='tight')
    print(f"[+] Multi-layer analysis completed. Plot generated in final_results/")

if __name__ == "__main__":
    main()