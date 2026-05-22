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

    print("[*] Loading Mode 1 (Pulse Attack) data...")
    # 【已修改】強制讀取 _mode1 的 CSV 檔案
    df_native = load_data('vanetza_unpatched', 'qos_attack_10.0_mode1.csv')
    df_filter = load_data('vanetza_unpatched', 'qos_attack_10.0_mode1_filtered.csv')

    if df_native is None or df_filter is None:
        print("[-] Data missing. Make sure you ran the C++ program with -m 1.")
        return

    # 脈衝攻擊區間 (對應 C++ 的 Mode 1: 30% ~ 50%)
    attack_start = 300000 
    attack_end = 500000
    
    # 觀察區間 (Zoom In)
    plot_start = 250000
    plot_end = 600000

    df_native_zoom = df_native[(df_native['packet_id'] >= plot_start) & (df_native['packet_id'] <= plot_end)]
    df_filter_zoom = df_filter[(df_filter['packet_id'] >= plot_start) & (df_filter['packet_id'] <= plot_end)]

    plt.rcParams.update({'font.size': 12, 'axes.labelsize': 14, 'axes.titlesize': 14, 'font.family': 'serif'})
    fig, ax = plt.subplots(figsize=(14, 6))

    ax.plot(df_native_zoom['packet_id'], df_native_zoom['latency_ms'], 
            label='Unpatched Native (No Defense)', color='#d62728', linewidth=1.0, alpha=0.5)
    ax.plot(df_filter_zoom['packet_id'], df_filter_zoom['latency_ms'], 
            label='Proposed FSM Filter', color='#1f77b4', linewidth=1.2, alpha=0.9)

    ax.axvspan(attack_start, attack_end, color='gray', alpha=0.2, label='Pulse Attack Window')

    ax.set_ylim(0, 0.45) 
    ax.set_xlim(plot_start, plot_end)
    ax.set_xlabel('Packet ID (Chronological Order)')
    ax.set_ylabel('Processing Latency (ms)')
    ax.set_title('Dynamic Resilience: System Recovery Under Pulse Attack')
    ax.grid(True, linestyle=':', alpha=0.7)
    ax.legend(loc='upper right')

    plt.tight_layout()
    out_file = os.path.join(output_dir, 'pulse_recovery_timeline.png')
    fig.savefig(out_file, dpi=300, bbox_inches='tight')
    print(f"[+] Pulse recovery timeline saved to {out_file}")

if __name__ == "__main__":
    main()