#!/bin/bash

export LC_ALL=C

# ==========================================
# V2X QoS Experiment Automation Script
# ==========================================

# Configuration
TOTAL_PACKETS=1000000
RATES=(1.0 5.0 10.0)
CORE=7

# Attack mode selection (0=Uniform, 1=Single Pulse, 2=Periodic On-Off)
ATTACK_MODE=2

EXEC="/home/yhl/term-project/cse625_qos/vanetza_unpatched/build/bin/qos_measure"

echo "================================================="
echo " Starting QoS Experiments (Pinned to Core: $CORE)"
echo " Selected Attack Mode: $ATTACK_MODE"
echo "================================================="

mkdir -p csv_data
mkdir -p result

for rate in "${RATES[@]}"; do
    echo "-------------------------------------------------"
    echo "[*] Test Group: $rate% Malicious Packets | Mode: $ATTACK_MODE"
    
    # Native version (No defense)
    taskset -c $CORE $EXEC -t $TOTAL_PACKETS -p $rate -m $ATTACK_MODE
    
    # Proposed Pre-filter version
    taskset -c $CORE $EXEC -t $TOTAL_PACKETS -p $rate -m $ATTACK_MODE -f
done

echo "================================================="
echo " Data collection complete."
echo "================================================="