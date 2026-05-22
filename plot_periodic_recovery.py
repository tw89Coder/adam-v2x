import pandas as pd
import matplotlib.pyplot as plt
import os

def load_data(repo_name, filename):
    base_path = os.path.dirname(os.path.abspath(__file__))
    filepath = os.path.join(base_path, repo_name, 'tools', 'qos-harness', 'csv_data', filename)
    if not os.path.exists(filepath):
        print(f"[Warning] File not found: {filepath}")
        return None
    df = pd.read_csv(filepath)
    df['latency_ms'] = df['latency_ns'] / 1e6
    return df

def main():
    base_path = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(base_path, 'final_results')
    os.makedirs(output_dir, exist_ok=True)

    print("[*] Loading Mode 2 (Periodic On-Off Attack) data...")
    df_native = load_data('vanetza_unpatched', 'qos_attack_10.0_mode2.csv')
    df_filter = load_data('vanetza_unpatched', 'qos_attack_10.0_mode2_filtered.csv')

    if df_native is None or df_filter is None:
        print("[-] Data missing. Make sure you ran the C++ program with -m 2.")
        return

    # ==========================================
    # 訊號降噪：計算滑動平均 (Moving Average)
    # 每 500 顆封包取一次平均，撫平 OS Jitter
    # ==========================================
    print("[*] Applying Signal Smoothing (Rolling Mean)...")
    window_size = 500
    df_native['smoothed_latency'] = df_native['latency_ms'].rolling(window=window_size, min_periods=1).mean()
    df_filter['smoothed_latency'] = df_filter['latency_ms'].rolling(window=window_size, min_periods=1).mean()

    plt.rcParams.update({'font.size': 12, 'axes.labelsize': 14, 'axes.titlesize': 14, 'font.family': 'serif'})
    fig, ax = plt.subplots(figsize=(16, 6))

    # ==========================================
    # 圖層 1：原始資料的背景陰影 (低透明度，展現真實感但不過度干擾)
    # ==========================================
    # 藍線在底層 (zorder=1)
    ax.plot(df_filter['packet_id'], df_filter['latency_ms'], color='#1f77b4', linewidth=0.5, alpha=0.1, zorder=1)
    # 紅線在上層 (zorder=2)
    ax.plot(df_native['packet_id'], df_native['latency_ms'], color='#d62728', linewidth=0.5, alpha=0.1, zorder=2)

    # ==========================================
    # 圖層 2：平滑後的趨勢實線 (核心重點，修正 Z-Order)
    # ==========================================
    # 先畫藍線趨勢 (zorder=3)，證明和平時期貼底，攻擊時期依然被壓制
    ax.plot(df_filter['packet_id'], df_filter['smoothed_latency'], 
            label='Proposed FSM Filter (Smoothed)', color='#1f77b4', linewidth=1.5, alpha=0.9, zorder=3)
    
    # 後畫紅線趨勢 (zorder=4)，證明在攻擊區間真實的飆高情況
    ax.plot(df_native['packet_id'], df_native['smoothed_latency'], 
            label='Unpatched Native (Smoothed)', color='#d62728', linewidth=1.5, alpha=0.9, zorder=4)

    # ==========================================
    # 繪製 5 個週期的背景高亮 (灰色區塊)
    # ==========================================
    total_packets = 1000000
    period_length = total_packets // 10
    added_span_legend = False 
    
    for cycle in range(10):
        if cycle % 2 == 1: # 奇數區間 (1, 3, 5, 7, 9)
            start_idx = cycle * period_length
            end_idx = (cycle + 1) * period_length
            if not added_span_legend:
                ax.axvspan(start_idx, end_idx, color='gray', alpha=0.2, label='Attack Active Window')
                added_span_legend = True
            else:
                ax.axvspan(start_idx, end_idx, color='gray', alpha=0.2)

    # 設定圖表外觀
    ax.set_ylim(0, 0.45) 
    ax.set_xlim(0, total_packets)
    ax.set_xlabel('Packet ID (Chronological Order)')
    ax.set_ylabel('Processing Latency (ms)')
    ax.set_title('State Flapping Resilience: System Stability Under Periodic Attacks')
    ax.grid(True, linestyle=':', alpha=0.7)
    
    # 調整圖例位置
    ax.legend(loc='upper right')

    plt.tight_layout()
    out_file = os.path.join(output_dir, 'periodic_recovery_timeline.png')
    fig.savefig(out_file, dpi=300, bbox_inches='tight')
    print(f"[+] Periodic recovery timeline saved to {out_file}")

if __name__ == "__main__":
    main()