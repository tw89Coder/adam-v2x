#!/bin/bash

# ==============================================================================
# V2X QoS Large-Scale Simulation and Analytics Control Console
# ==============================================================================

export LC_ALL=C
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Academic hardware constraints: pin execution thread to prevent OS schedule jitter
PIN_CORE=9
TOTAL_PACKETS=1000000

print_usage() {
    echo "Usage: ./run_experiments.sh [target] [action] [optional args...]"
    echo "Targets:"
    echo "  unpatched       Run tasks against the unpatched system workspace"
    echo "  patched         Run tasks against the patched system workspace"
    echo "  all             Sequentially run entire matrix for BOTH unpatched and patched"
    echo "Actions:"
    echo "  --diagnose-flood  Execute short flood region parsing delta diagnosis"
    echo "  --profile-amp     Run full geometric size sweep tracking MTU capacity scaling"
    echo "  --build-dataset   Generate and validate high-potency toxic exploit vectors"
    echo "  --simulate-all    Execute nested sweep matrix across ALL modes (0,1,2) and rates (1%,5%,10%)"
    echo "  --custom          Manually bypass defaults to feed raw runtime arguments directly"
    exit 1
}

TARGET=$1
ACTION=$2

if [ -z "$TARGET" ] || { [ "$TARGET" != "unpatched" ] && [ "$TARGET" != "patched" ] && [ "$TARGET" != "all" ]; } || [ -z "$ACTION" ]; then
    print_usage
fi

execute_matrix_sweep() {
    local tgt=$1
    local exec_bin="${ROOT_DIR}/vanetza_${tgt}/build/bin/qos-harness"

    if [ ! -f "$exec_bin" ]; then
        echo "[-] Error: Executable target kernel missing at ${exec_bin}."
        echo "[-] Run './manage_build.sh ${tgt}' first to map compilation binary."
        return
    fi

    mkdir -p "${ROOT_DIR}/outputs/csv_raw/${tgt}"

    # FULL ACADEMIC MATRIX DEFINITIONS (All attack profiles X All pollution densities)
    local MODES=(0 1 2)
    local POLLUTION_RATES=(1.0 5.0 10.0)

    for mode in "${MODES[@]}"; do
        for rate in "${POLLUTION_RATES[@]}"; do
            echo "======================================================================"
            echo "[*] Launching Matrix Node: Target=${tgt} | Rate=${rate}% | Mode=${mode}"
            echo "======================================================================"
            
            if [ "$tgt" == "unpatched" ]; then
                taskset -c $PIN_CORE "$exec_bin" -t $TOTAL_PACKETS -p "$rate" -m "$mode"
            else
                taskset -c $PIN_CORE "$exec_bin" -t $TOTAL_PACKETS -p "$rate" -m "$mode" -f
            fi
            
            # CRITICAL: Emit explicit trailing newline to force terminal view tracking down on block completions
            echo ""
            echo "----------------------------------------------------------------------"
        done
    done
}

case "$ACTION" in
    --diagnose-flood|--profile-amp|--build-dataset)
        if [ "$TARGET" == "all" ]; then
            echo "[-] Error: Action ${ACTION} must be target specific. Choose unpatched or patched."
            exit 1
        fi
        EXEC_BIN="${ROOT_DIR}/vanetza_${TARGET}/build/bin/qos-harness"
        echo "[*] Triggering dedicated framework routine: ${ACTION} (Pinned Core: ${PIN_CORE})"
        taskset -c $PIN_CORE "$EXEC_BIN" "$ACTION"
        ;;
        
    --simulate-all)
        if [ "$TARGET" == "all" ]; then
            execute_matrix_sweep "unpatched"
            execute_matrix_sweep "patched"
        else
            execute_matrix_sweep "$TARGET"
        fi
        echo "======================================================================"
        echo "[+] Complete sweep matrix executed. Telemetry logs stabilized."
        echo "======================================================================"
        ;;
        
    --custom)
        if [ "$TARGET" == "all" ]; then
            echo "[-] Error: Custom actions cannot accept global target routing."
            exit 1
        fi
        shift 2
        EXEC_BIN="${ROOT_DIR}/vanetza_${TARGET}/build/bin/qos-harness"
        echo "[*] Invoking custom framework map... Args: $@"
        taskset -c $PIN_CORE "$EXEC_BIN" "$@"
        ;;
        
    *)
        print_usage
        ;;
esac