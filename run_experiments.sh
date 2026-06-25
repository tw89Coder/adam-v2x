#!/bin/bash

# ==============================================================================
# V2X QoS Large-Scale Simulation and Analytics Control Console
# ==============================================================================

export LC_ALL=C
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Initialize terminal signaling color codes
C_RESET="\033[0m"
C_BOLD="\033[1m"
C_INFO="\033[1;36m"
C_SUCCESS="\033[1;32m"
C_WARN="\033[1;33m"
C_ERROR="\033[1;41;37m"

# Initialize baseline default states and matrix parameters
PIN_CORE=${PIN_CORE:-9}
TOTAL_PACKETS=1000000
RUN_FILTER_OFF=true
RUN_FILTER_ON=true

# Default global state machine mode and pollution density spectrum arrays
DEFAULT_MODES=(0 1 2)
TARGET_MODES=("${DEFAULT_MODES[@]}")

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
                echo -e "${C_ERROR}[ERROR] --core demands a valid numeric CPU index value.${C_RESET}"
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
        --modes)
            if [[ -n "$2" ]]; then
                # Tokenize space-separated string into bash array elements
                IFS=' ' read -r -a TARGET_MODES <<< "$2"
                shift 2
            else
                echo -e "${C_ERROR}[ERROR] --modes demands a space-separated string of integers (e.g. \"0 1\").${C_RESET}"
                exit 1
            fi
            ;;
        --rates)
            if [[ -n "$2" ]]; then
                # Tokenize space-separated string into bash array elements
                IFS=' ' read -r -a POLLUTION_RATES <<< "$2"
                shift 2
            else
                echo -e "${C_ERROR}[ERROR] --rates demands a space-separated string of ranges (e.g. \"1.0 5.0\").${C_RESET}"
                exit 1
            fi
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

# Restore standard target routing tokens back to the positional parameter map
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
    echo "  --train-rl        Trigger automated one-click RL training pipeline (Forces Mode 3 + Socket Sync)"
    echo "  --custom          Manually bypass defaults to feed raw runtime arguments directly"
    echo ""
    echo "Automation Configuration Modifiers (Can be placed anywhere):"
    echo "  -c, --core <id>   Target hardware CPU core index for taskset processor locking (Default: 9)"
    echo "  --no-filter-only  Force --simulate-all batch scheduler to execute ONLY Filter=OFF steps"
    echo "  --filter-only     Force --simulate-all batch scheduler to execute ONLY Filter=ON steps"
    echo "  --modes \"m1 m2\"   Override default execution suite with custom target logic modes"
    echo "  --rates \"r1 r2\"   Override default sweep steps with a custom range list of pollution floats"
    echo ""
    echo "Examples:"
    echo "  ./run_experiments.sh unpatched --simulate-all                             # Default 18-node sweep"
    echo "  ./run_experiments.sh unpatched --train-rl                                 # Launch one-click RL training Sandbox"
    echo "  ./run_experiments.sh all --simulate-all --modes \"0\" --rates \"0.0\"         # Generate absolute baselines"
    exit 1
}

TARGET=$1
ACTION=$2

if [ -z "$TARGET" ] || { [ "$TARGET" != "unpatched" ] && [ "$TARGET" != "patched" ] && [ "$TARGET" != "all" ]; } || [ -z "$ACTION" ]; then
    print_usage
fi

# ── NEW: Dedicated Modular Pipeline Function for RL Training ────────────────
execute_rl_training() {
    local tgt=$1
    local exec_bin="${ROOT_DIR}/vanetza_${tgt}/build/bin/qos-harness"

    if [ ! -f "$exec_bin" ]; then
        echo -e "${C_ERROR}[FATAL] Executable target kernel missing at ${exec_bin}.${C_RESET}"
        echo -e "${C_ERROR}[FATAL] Run './manage_build.sh ${tgt}' first to compile binary map.${C_RESET}"
        exit 1
    fi

    # Ensure isolation directory structures exist before firing synchronization lines
    mkdir -p "${ROOT_DIR}/outputs/rl_env"

    echo -e "${C_WARN}[NOTICE] Initializing Collaborative DRL Core Infrastructure Server Connection...${C_RESET}"
    echo -e "${C_INFO}[STAGE] Task Lock Active: Target=${tgt} | Mode=3 (Grand Mix Scenario) | Automation Flags=--rl (Core: ${PIN_CORE})${C_RESET}"

    # Sequentially iterate through configuration sweeps to feed interactive socket state-spaces
    for rate in "${POLLUTION_RATES[@]}"; do
        echo -e "${C_INFO}[EXEC] Pushing dynamic training trace trajectory at rate: ${rate}%...${C_RESET}"
        taskset -c $PIN_CORE "$exec_bin" -t $TOTAL_PACKETS -p "$rate" -m 3 --rl
        echo "----------------------------------------------------------------------"
    done
}

execute_matrix_sweep() {
    local tgt=$1
    local exec_bin="${ROOT_DIR}/vanetza_${tgt}/build/bin/qos-harness"

    if [ ! -f "$exec_bin" ]; then
        echo -e "${C_ERROR}[FATAL] Executable target kernel missing at ${exec_bin}.${C_RESET}"
        echo -e "${C_ERROR}[FATAL] Run './manage_build.sh ${tgt}' first to compile binary map.${C_RESET}"
        exit 1
    fi

    mkdir -p "${ROOT_DIR}/outputs/csv_raw/${tgt}"

    # Dynamic target mode list mapped from command arguments
    for mode in "${TARGET_MODES[@]}"; do
        for rate in "${POLLUTION_RATES[@]}"; do
            
            # Conditionally execute the unhardened raw baseline telemetry flow node
            if [ "$RUN_FILTER_OFF" = true ]; then
                echo -e "${C_INFO}[STAGE] Node Init: Target=${tgt} | Rate=${rate}% | Mode=${mode} | Filter=OFF (Core: ${PIN_CORE})${C_RESET}"
                taskset -c $PIN_CORE "$exec_bin" -t $TOTAL_PACKETS -p "$rate" -m "$mode"
            fi

            # Conditionally execute the circuit-breaker state-machine hardened flow node
            if [ "$RUN_FILTER_ON" = true ]; then
                echo -e "${C_INFO}[STAGE] Node Init: Target=${tgt} | Rate=${rate}% | Mode=${mode} | Filter=ON  (Core: ${PIN_CORE})${C_RESET}"
                taskset -c $PIN_CORE "$exec_bin" -t $TOTAL_PACKETS -p "$rate" -m "$mode" -f
            fi
            
            if [ "$RUN_FILTER_OFF" = true ] || [ "$RUN_FILTER_ON" = true ]; then
                echo "----------------------------------------------------------------------"
            fi
        done
    done
}

case "$ACTION" in
    --diagnose-flood|--profile-amp|--build-dataset)
        execute_single_action() {
            local tgt=$1
            local bin="${ROOT_DIR}/vanetza_${tgt}/build/bin/qos-harness"
            
            if [ ! -f "$bin" ]; then
                echo -e "${C_ERROR}[FATAL] Executable target kernel missing at ${bin}.${C_RESET}"
                echo -e "${C_ERROR}[FATAL] Run './manage_build.sh ${tgt}' first to compile binary map.${C_RESET}"
                exit 1
            fi
            
            echo -e "${C_INFO}[INFO] Triggering dedicated framework routine: ${ACTION} on target [${tgt}] (Pinned Core: ${PIN_CORE})${C_RESET}"
            taskset -c $PIN_CORE "$bin" "$ACTION"
            
            # Post-execution isolation router to prevent cross-over overwrites
            local target_csv_dir="${ROOT_DIR}/outputs/csv_raw/${tgt}"
            mkdir -p "$target_csv_dir"
            
            # Intercept and relocate generated profile data from shared or local drop zones
            if [ -f "${ROOT_DIR}/outputs/csv_raw/amplification_profile.csv" ]; then
                mv "${ROOT_DIR}/outputs/csv_raw/amplification_profile.csv" "${target_csv_dir}/"
                echo -e "${C_SUCCESS}[SUCCESS] Dynamic isolation complete: Relocated root profile to ${tgt}/ layout.${C_RESET}"
            elif [ -f "${ROOT_DIR}/vanetza_${tgt}/tools/qos-harness/csv_data/amplification_profile.csv" ]; then
                mv "${ROOT_DIR}/vanetza_${tgt}/tools/qos-harness/csv_data/amplification_profile.csv" "${target_csv_dir}/"
                echo -e "${C_SUCCESS}[SUCCESS] Dynamic isolation complete: Relocated localized profile to ${tgt}/ layout.${C_RESET}"
            fi
        }

        # Upgraded to natively support sequential automation sweeps via the 'all' keyword
        if [ "$TARGET" == "all" ]; then
            execute_single_action "unpatched"
            execute_single_action "patched"
        else
            execute_single_action "$TARGET"
        fi
        ;;
        
    --simulate-all)
        if [ "$TARGET" == "all" ]; then
            execute_matrix_sweep "unpatched"
            execute_matrix_sweep "patched"
        else
            execute_matrix_sweep "$TARGET"
        fi
        echo -e "${C_SUCCESS}[SUCCESS] Dynamic matrix sweep executed successfully. Data converged.${C_RESET}"
        ;;

    # ── NEW: Dedicated Switch Branch Routing for Automated Training ──────────
    --train-rl)
        if [ "$TARGET" == "all" ]; then
            execute_rl_training "unpatched"
            execute_rl_training "patched"
        else
            execute_rl_training "$TARGET"
        fi
        echo -e "${C_SUCCESS}[SUCCESS] Interactive RL training pipeline execution complete. Telemetry converged.${C_RESET}"
        ;;
        
    --custom)
        if [ "$TARGET" == "all" ]; then
            echo -e "${C_ERROR}[ERROR] Custom actions cannot accept global target routing.${C_RESET}"
            exit 1
        fi
        shift 2
        EXEC_BIN="${ROOT_DIR}/vanetza_${TARGET}/build/bin/qos-harness"
        echo -e "${C_INFO}[INFO] Invoking custom framework map... Args: $@${C_RESET}"
        taskset -c $PIN_CORE "$EXEC_BIN" "$@"
        ;;
        
    *)
        print_usage
        ;;
esac