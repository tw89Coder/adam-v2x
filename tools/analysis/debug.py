import pandas as pd

def load_data(repo_name, filename):
    import os
    base_path = os.path.dirname(os.path.abspath(__file__))
    filepath = os.path.join(base_path, repo_name, 'tools', 'qos-harness',
                            'csv_data', filename)
    if not os.path.exists(filepath):
        print(f"[Warning] File not found: {filepath}")
        return None
    df = pd.read_csv(filepath)
    df['latency_ms'] = df['latency_ns'] / 1e6
    return df

df_native = load_data('vanetza_unpatched', 'qos_attack_10.0_mode1.csv')
df_filter  = load_data('vanetza_unpatched', 'qos_attack_10.0_mode1_filtered.csv')

total = max(df_native['packet_id'].max(), df_filter['packet_id'].max())
atk_s = int(total * 0.30)
atk_e = int(total * 0.50)

nat_atk  = df_native[(df_native['packet_id'].between(atk_s, atk_e)) & (df_native['is_malware']==0)]
filt_atk = df_filter[(df_filter['packet_id'].between(atk_s, atk_e)) & (df_filter['was_dropped']==0)]
nat_pre  = df_native[(df_native['packet_id'] < atk_s) & (df_native['is_malware']==0)]
filt_pre = df_filter[(df_filter['packet_id'] < atk_s) & (df_filter['was_dropped']==0)]

dropped      = df_filter[(df_filter['packet_id'].between(atk_s, atk_e)) & (df_filter['was_dropped']==1)]
total_in_atk = len(df_filter[df_filter['packet_id'].between(atk_s, atk_e)])

# False positive rate (safe packets wrongly dropped)
fp = df_filter[(df_filter['is_malware']==0) & (df_filter['was_dropped']==1)]
total_safe = len(df_filter[df_filter['is_malware']==0])

print("=== BEFORE ATTACK ===")
print(f"Unpatched  median={nat_pre['latency_ms'].median():.4f}  p99={nat_pre['latency_ms'].quantile(0.99):.4f}")
print(f"FSM filter median={filt_pre['latency_ms'].median():.4f}  p99={filt_pre['latency_ms'].quantile(0.99):.4f}")

print("\n=== DURING ATTACK (legitimate only) ===")
print(f"Unpatched  median={nat_atk['latency_ms'].median():.4f}  p99={nat_atk['latency_ms'].quantile(0.99):.4f}  n={len(nat_atk)}")
print(f"FSM filter median={filt_atk['latency_ms'].median():.4f}  p99={filt_atk['latency_ms'].quantile(0.99):.4f}  n={len(filt_atk)}")

print(f"\n=== DROP RATE during attack ===")
print(f"Dropped {len(dropped)}/{total_in_atk} = {100*len(dropped)/total_in_atk:.1f}%")

print(f"\n=== FALSE POSITIVE RATE ===")
print(f"Safe packets wrongly dropped: {len(fp)}/{total_safe} = {100*len(fp)/total_safe:.2f}%")