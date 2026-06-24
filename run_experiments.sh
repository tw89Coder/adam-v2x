#!/bin/bash

# ==============================================================================
# V2X QoS Large-Scale Simulation and Analytics Control Console
# ==============================================================================

export LC_ALL=C
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Initialize baseline default states and matrix parameters
PIN_CORE=${PIN_CORE:-9}
TOTAL_PACKETS=1000000
RUN_FILTER_OFF=true
RUN_FILTER_ON=true

# Default global pollution density spectrum arrays
DEFAULT_RATES=(1.0 5.0 10.0)
POLLUTION_RATES=("${DEFAULT_RATES[@]}")

# ------------------------------------------------------------------------------
# Dynamic Argument Filtering Loop: Parse custom flags from anywhere in CLI
# ------------------------------------------------------------------------------
POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--core)
            if [[ -n "$2" && "$2" =~ ^[0-9]+$ ]]; then
                PIN_CORE="$2"
                shift 2
            else
                echo "[-] Error: --core demands a valid numeric CPU index value."
                exit 1
            fi
            ;;
        --no-filter-only)
            RUN_FILTER_OFF=true
            RUN_FILTER_ON=false
            shift
            ;;
        --filter-only)
            RUN_FILTER_OFF=false
            RUN_FILTER_ON=true
            shift
            ;;
        --rates)
            if [[ -n "$2" ]]; then
                # Dynamically tokenized whitespace separated numbers into native Bash array mapping
                IFS=' ' read -r -a POLLUTION_RATES <<< "$2"
                shift 2
            else
                echo "[-] Error: --rates demands a string space-separated list of ranges (e.g. \"1.0 2.0 3.0\")."
                exit 1
            fi
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

# Restore standard target routing tokens back to the main branch execution map
set -- "${POSITIONAL_ARGS[@]}"

print_usage() {
    echo "Usage: ./run_experiments.sh [target] [action] [optional flags...]"
    echo "Targets:"
    echo "  unpatched       Run tasks against the unpatched system workspace"
    echo "  patched         Run tasks against the patched system workspace"
    echo "  all             Sequentially run entire matrix for BOTH unpatched and patched"
    echo "Actions:"
    echo "  --diagnose-flood  Execute short flood region parsing delta diagnosis"
    echo "  --profile-amp     Run full geometric size sweep tracking MTU capacity scaling"
    echo "  --build-dataset   Generate and validate high-potency toxic exploit vectors"
    echo "  --simulate-all    Execute matrix sweep dynamically configured by runtime filters/ranges"
    echo "  --custom          Manually bypass defaults to feed raw runtime arguments directly"
    echo ""
    echo "Automation Configuration Modifiers (Can be placed anywhere):"
    echo "  -c, --core <id>   Target hardware CPU core index for taskset processor locking (Default: 9)"
    echo "  --no-filter-only  Force --simulate-all batch scheduler to execute ONLY Filter=OFF steps"
    echo "  --filter-only     Force --simulate-all batch scheduler to execute ONLY Filter=ON steps"
    echo "  --rates \"r1 r2\"   Override default sweep steps with a custom range list of pollution floats"
    echo ""
    echo "Examples:"
    echo "  ./run_experiments.sh unpatched --simulate-all                             # Default 18-node sweep"
    echo "  ./run_experiments.sh unpatched --simulate-all --no-filter-only            # Only Filter=OFF nodes"
    echo "  ./run_experiments.sh unpatched --simulate-all --rates \"1.0 2.0 3.0 4.0\"   # Sweep 4 custom rates"
    echo "  ./run_experiments.sh unpatched --simulate-all --filter-only --rates \"2.5 7.5\" --core 4"
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

    # Dynamic target mode list matrix array
    local MODES=(0 1 2)

    for mode in "${MODES[@]}"; do
        for rate in "${POLLUTION_RATES[@]}"; do
            
            # Conditionally execute the unhardened raw baseline telemetry flow node
            if [ "$RUN_FILTER_OFF" = true ]; then
                echo "======================================================================"
                echo "[*] Matrix Node: Target=${tgt} | Rate=${rate}% | Mode=${mode} | Filter=OFF (Core: ${PIN_CORE})"
                echo "======================================================================"
                taskset -c $PIN_CORE "$exec_bin" -t $TOTAL_PACKETS -p "$rate" -m "$mode"
                echo "" # Releases trailing carriage return view block
            fi

            # Conditionally execute the circuit-breaker state-machine hardened flow node
            if [ "$RUN_FILTER_ON" = true ]; then
                echo "======================================================================"
                echo "[*] Matrix Node: Target=${tgt} | Rate=${rate}% | Mode=${mode} | Filter=ON (Core: ${PIN_CORE})"
                echo "======================================================================"
                taskset -c $PIN_CORE "$exec_bin" -t $TOTAL_PACKETS -p "$rate" -m "$mode" -f
                echo ""
            fi
            
            if [ "$RUN_FILTER_OFF" = true ] || [ "$RUN_FILTER_ON" = true ]; then
                echo "----------------------------------------------------------------------"
            fi
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
        echo "[+] Dynamic matrix sweep executed successfully. Data converged."
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