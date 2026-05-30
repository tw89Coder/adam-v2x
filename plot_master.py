import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os

MODES = [0, 1, 2]
RATES = [1.0, 5.0, 10.0]
WARMUP = 50
JITTER_THRESHOLD_MS = 5.0

def load_data(repo_name, filename, warmup=WARMUP):
    base_path = os.path.dirname(os.path.abspath(__file__))
    filepath = os.path.join(base_path, repo_name, 'tools', 'qos-harness', 'csv_data', filename)
    if not os.path.exists(filepath):
        print(f"  [Skip] File not found: {filepath}")
        return None
    df = pd.read_csv(filepath)
    df['latency_ms'] = df['latency_ns'] / 1e6

    # Remove warm-up samples
    df = df.iloc[warmup:].reset_index(drop=True)

    # Filter OS jitter outliers (>5ms, well above real attack peak ~1.5ms)
    before = len(df)
    df = df[df['latency_ms'] < JITTER_THRESHOLD_MS].reset_index(drop=True)
    after = len(df)
    if before != after:
        print(f"  [Jitter] Removed {before - after} OS outliers (>5ms) from {filename}")

    return df


def compute_security_metrics(df):
    """
    Calculate FPR and FNR from 'was_dropped' and 'is_malware' columns.

    Confusion matrix:
      TP = malicious packet correctly blocked   (is_malware=1, was_dropped=1)
      FP = benign packet wrongly blocked        (is_malware=0, was_dropped=1)
      TN = benign packet correctly admitted     (is_malware=0, was_dropped=0)
      FN = malicious packet wrongly admitted    (is_malware=1, was_dropped=0)

    FPR (%) = FP / (FP + TN) * 100   — how often benign traffic is blocked
    FNR (%) = FN / (FN + TP) * 100   — how often malicious traffic slips through
    """
    if 'was_dropped' not in df.columns or 'is_malware' not in df.columns:
        return 'N/A', 'N/A'

    tp = len(df[(df['is_malware'] == 1) & (df['was_dropped'] == 1)])
    fp = len(df[(df['is_malware'] == 0) & (df['was_dropped'] == 1)])
    tn = len(df[(df['is_malware'] == 0) & (df['was_dropped'] == 0)])
    fn = len(df[(df['is_malware'] == 1) & (df['was_dropped'] == 0)])

    fpr = round((fp / (fp + tn)) * 100.0, 4) if (fp + tn) > 0 else 0.0
    fnr = round((fn / (fn + tp)) * 100.0, 4) if (fn + tp) > 0 else 0.0
    return fpr, fnr


def compute_stats(df, is_filtered=False):
    """
    Compute latency statistics. For filtered files also compute FPR/FNR
    from the was_dropped + is_malware columns (latency stats use admitted
    packets only, i.e. was_dropped == 0).
    Returns a dict, or None if df is None.
    """
    if df is None:
        return None

    # For filtered files: latency stats are measured on admitted packets only
    if is_filtered and 'was_dropped' in df.columns:
        df_admitted = df[df['was_dropped'] == 0].reset_index(drop=True)
    else:
        df_admitted = df

    if df_admitted.empty:
        return None

    fpr, fnr = compute_security_metrics(df) if is_filtered else ('N/A', 'N/A')

    return {
        "Mean_ms":   round(df_admitted['latency_ms'].mean(), 4),
        "Median_ms": round(df_admitted['latency_ms'].median(), 4),
        "P99_ms":    round(df_admitted['latency_ms'].quantile(0.99), 4),
        "P99.9_ms":  round(df_admitted['latency_ms'].quantile(0.999), 4),
        "Max_ms":    round(df_admitted['latency_ms'].max(), 4),
        "FPR_%":     fpr,
        "FNR_%":     fnr,
    }


def plot_cdf(ax, data, label, color, linestyle, linewidth, zorder):
    if data is None:
        return
    sorted_data = np.sort(data)
    yvals = np.arange(len(sorted_data)) / float(len(sorted_data) - 1)
    ax.plot(sorted_data, yvals, label=label, color=color,
            linestyle=linestyle, linewidth=linewidth, alpha=0.9, zorder=zorder)


def main():
    base_path = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(base_path, 'final_results')
    os.makedirs(output_dir, exist_ok=True)

    # ==========================================
    # 1. Collect stats across ALL combinations
    # ==========================================
    rows = []

    print("\n[*] Scanning all mode × rate × patch × filter combinations...\n")

    # --- Baseline (no attack, no mode/rate) ---
    df_base = load_data('vanetza_unpatched', 'qos_baseline.csv')
    s = compute_stats(df_base, is_filtered=False)
    if s:
        rows.append({
            "Scenario":   "Baseline (No Attack)",
            "Repo":       "vanetza_unpatched",
            "Mode":       "N/A",
            "Rate_%":     0.0,
            "Variant":    "Native",
            **s
        })

    # --- Attack combinations ---
    for mode in MODES:
        for rate in RATES:
            rate_str = f"{rate}"
            combos = [
                ("vanetza_unpatched", f"qos_attack_{rate_str}_mode{mode}.csv",          "Unpatched", "Native",   False),
                ("vanetza_unpatched", f"qos_attack_{rate_str}_mode{mode}_filtered.csv", "Unpatched", "Filtered", True),
                ("vanetza_patched",   f"qos_attack_{rate_str}_mode{mode}.csv",          "Patched",   "Native",   False),
                ("vanetza_patched",   f"qos_attack_{rate_str}_mode{mode}_filtered.csv", "Patched",   "Filtered", True),
            ]
            for repo, filename, patch_label, variant_label, is_filtered in combos:
                print(f"  Loading  mode{mode}  {rate}%  {patch_label}  {variant_label}")
                df = load_data(repo, filename)
                s = compute_stats(df, is_filtered=is_filtered)
                if s:
                    rows.append({
                        "Scenario": f"{patch_label} {variant_label} | mode{mode} | {rate}%",
                        "Repo":     repo,
                        "Mode":     f"mode{mode}",
                        "Rate_%":   rate,
                        "Variant":  f"{patch_label}+{variant_label}",
                        **s
                    })

    # ==========================================
    # 2. Save master CSV
    # ==========================================
    stats_df = pd.DataFrame(rows)
    csv_path = os.path.join(output_dir, 'qos_all_combinations.csv')
    stats_df.to_csv(csv_path, index=False)

    print("\n" + "="*100)
    print(" 📊 QoS All-Combination Statistics Table (Latency + FPR + FNR)")
    print("="*100)
    pd.set_option('display.max_rows', None)
    pd.set_option('display.max_columns', None)
    pd.set_option('display.width', 200)
    print(stats_df.to_string(index=False))
    print("="*100)
    print(f"\n[+] Full CSV saved to: {csv_path}\n")

    # ==========================================
    # 3. Per-mode master plot (original style)
    # ==========================================
    plt.rcParams.update({
        'font.size': 12,
        'axes.labelsize': 14,
        'axes.titlesize': 14,
        'font.family': 'serif'
    })

    # Colour / style palette per variant
    STYLE = {
        "Baseline (No Attack)":    ('#2ca02c', '-',  1),
        "Unpatched+Native":        ('#d62728', '-',  2),
        "Unpatched+Filtered":      ('#ff7f0e', ':',  3),
        "Patched+Native":          ('#9467bd', '--', 4),
        "Patched+Filtered":        ('#1f77b4', '-.', 5),
    }

    WINDOW = 500

    for mode in MODES:
        for rate in RATES:
            rate_str = f"{rate}"
            print(f"[*] Plotting mode{mode} @ {rate}% ...")

            # Load the 5 series for this subplot pair
            df_b   = load_data('vanetza_unpatched', 'qos_baseline.csv')
            df_un  = load_data('vanetza_unpatched', f'qos_attack_{rate_str}_mode{mode}.csv')
            df_unf = load_data('vanetza_unpatched', f'qos_attack_{rate_str}_mode{mode}_filtered.csv')
            df_p   = load_data('vanetza_patched',   f'qos_attack_{rate_str}_mode{mode}.csv')
            df_pf  = load_data('vanetza_patched',   f'qos_attack_{rate_str}_mode{mode}_filtered.csv')

            datasets = [
                ("Baseline (No Attack)", df_b,   STYLE["Baseline (No Attack)"]),
                ("Unpatched+Native",     df_un,  STYLE["Unpatched+Native"]),
                ("Unpatched+Filtered",   df_unf, STYLE["Unpatched+Filtered"]),
                ("Patched+Native",       df_p,   STYLE["Patched+Native"]),
                ("Patched+Filtered",     df_pf,  STYLE["Patched+Filtered"]),
            ]

            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))

            # ----- Left: Time Series -----
            for name, df, (color, ls, z) in datasets:
                if df is not None:
                    ax1.plot(df['packet_id'][:WINDOW], df['latency_ms'][:WINDOW],
                             label=name, color=color, linestyle=ls,
                             linewidth=1.5, alpha=0.4 if z == 1 else 0.8, zorder=z)

            ax1.set_ylim(0, 0.45)
            ax1.set_xlabel('Packet ID (Post Warm-up)')
            ax1.set_ylabel('Processing Latency (ms)')
            ax1.set_title(f'Latency Jitter — mode{mode} @ {rate}%')
            ax1.grid(True, linestyle=':', alpha=0.7)
            ax1.legend(loc='upper right', fontsize=10)

            # ----- Right: CDF -----
            for name, df, (color, ls, z) in datasets:
                if df is not None:
                    plot_cdf(ax2, df['latency_ms'], name, color, ls, 1.5, z)

            ax2.axhline(y=0.99, color='black', linestyle='-', alpha=0.2, linewidth=1.0)

            for idx, (name, df, (color, ls, z)) in enumerate(datasets):
                if df is not None:
                    p99 = df['latency_ms'].quantile(0.99)
                    ax2.plot([p99, p99], [0, 0.99], color=color, linestyle=ls,
                             linewidth=1.2, alpha=0.8)
                    ax2.text(p99 * 1.05, 0.2 + idx * 0.12,
                             f'{p99:.3f} ms', color=color, fontsize=10)

            ax2.set_xscale('log')
            ax2.set_xlim(1e-4, 10.0)
            ax2.set_xlabel('Processing Latency (ms) [Log Scale]')
            ax2.set_ylabel('CDF Probability')
            ax2.set_title(f'CDF (P99 Drop-lines) — mode{mode} @ {rate}%')
            ax2.grid(True, which="both", linestyle=':', alpha=0.7)
            ax2.legend(loc='lower right', fontsize=10)

            plt.tight_layout()
            fname = f'comparison_mode{mode}_{int(rate)}pct.png'
            fig.savefig(os.path.join(output_dir, fname), dpi=300, bbox_inches='tight')
            plt.close(fig)
            print(f"  [+] Saved {fname}")

    print("\n[✓] All done. Results in: final_results/")


if __name__ == "__main__":
    main()