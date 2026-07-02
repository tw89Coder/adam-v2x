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
C_ERROR="\033[1;31m"

# Print usage helper screen
print_usage() {
    echo -e "${C_BOLD}V2X QoS Large-Scale Simulation and Analytics Control Console${C_RESET}"
    echo -e "${C_INFO}Usage:${C_RESET} ./run_experiments.sh ${C_SUCCESS}[target]${C_RESET} ${C_WARN}[action]${C_RESET} [optional flags...]"
    echo -e ""
    echo -e "${C_BOLD}Targets:${C_RESET}"
    echo -e "  ${C_SUCCESS}unpatched${C_RESET}            Run tasks against the unpatched system workspace"
    echo -e "  ${C_SUCCESS}patched${C_RESET}              Run tasks against the patched system workspace"
    echo -e "  ${C_SUCCESS}all${C_RESET}                  Sequentially run entire matrix for BOTH unpatched and patched"
    echo -e "  ${C_SUCCESS}python${C_RESET}               Orchestrate Python DRL agent scripts (venv encapsulated)"
    echo -e ""
    echo -e "${C_BOLD}Actions under C++ targets (unpatched / patched / all):${C_RESET}"
    echo -e "  ${C_WARN}--diagnose-flood${C_RESET}      Execute short flood region parsing delta diagnosis"
    echo -e "  ${C_WARN}--profile-amp${C_RESET}         Run full geometric size sweep tracking MTU capacity scaling"
    echo -e "  ${C_WARN}--build-dataset${C_RESET}       Generate and validate high-potency toxic exploit vectors"
    echo -e "  ${C_WARN}--simulate-all${C_RESET}        Execute matrix sweep dynamically configured by runtime filters/ranges"
    echo -e "  ${C_WARN}--train-rl${C_RESET}            Trigger automated one-click RL training pipeline (Forces Mode 3 + Socket Sync)"
    echo -e "  ${C_WARN}--custom${C_RESET}              Manually bypass defaults to feed raw runtime arguments directly"
    echo -e ""
    echo -e "${C_BOLD}Actions under 'python' target:${C_RESET}"
    echo -e "  ${C_WARN}--train-online${C_RESET}       Start PPO interactive online socket server (port 8080)"
    echo -e "  ${C_WARN}--train-offline${C_RESET}      Run offline dataset trajectory training"
    echo -e "  ${C_WARN}--deploy${C_RESET}             Start production inference serve daemon"
    echo -e "  ${C_WARN}--verify-brain${C_RESET}       Audit brain checkpoints on baseline scenarios"
    echo -e "  ${C_WARN}--export-onnx${C_RESET}        Export trained PyTorch model weights to ONNX format"
    echo -e "  ${C_WARN}--plot${C_RESET}               Execute verification and plotting engine scripts"
    echo -e ""
    echo -e "${C_BOLD}Automation Configuration Modifiers (Short & Long Flags):${C_RESET}"
    echo -e "  ${C_INFO}-c, --core <id>${C_RESET}       Hardware CPU core index for taskset processor locking (Default: 9)"
    echo -e "  ${C_INFO}-n, --no-taskset${C_RESET}      Disable taskset core pinning (Bypasses core locking; recommended for RL)"
    echo -e "  ${C_INFO}-B, --baseline-only${C_RESET}   Execute ONLY Filter=OFF simulation steps (No mitigation)"
    echo -e "  ${C_INFO}-F, --filter-only${C_RESET}     Execute ONLY Filter=ON simulation steps (Mitigation active)"
    echo -e "  ${C_INFO}-m, --modes <\"modes\">${C_RESET}   Override default simulation scenario modes (Default: \"0 1 2\")."
    echo -e "                          Scenarios:"
    echo -e "                            0 = Uniform Random Attack (Malware dispersed randomly)"
    echo -e "                            1 = Single Pulse Attack (Sudden burst at 30%-50% window)"
    echo -e "                            2 = Periodic On-Off (5 waves of peak attack cycles)"
    echo -e "                            3 = Grand Mix Scenario (Dynamic hybrid mix for RL training)"
    echo -e "  ${C_INFO}-r, --rates <\"rates\">${C_RESET}   Override pollution rates (Default: \"1.0 5.0 10.0\")."
    echo -e "                          * \"mix\" blends multiple intensity traces (1.0%, 5.0%, 10.0% mode3 traces)"
    echo -e "                            to pre-train model checkpoints (Offline training only)."
    echo -e "  ${C_INFO}-o, --onnx [path]${C_RESET}     Enable in-process ONNX model inference during simulation"
    echo -e "  ${C_INFO}-s, --disable-safety${C_RESET}  Disable heuristic safety clamping boundaries for RL agent"
    echo -e ""
    echo -e "${C_BOLD}Examples:${C_RESET}"
    echo -e "  ./run_experiments.sh ${C_SUCCESS}unpatched${C_RESET} ${C_WARN}--simulate-all${C_RESET} -m \"0 1\" -r \"1.0 5.0\"      \033[90m# Run specific C++ sweep\033[0m"
    echo -e "  ./run_experiments.sh ${C_SUCCESS}python${C_RESET} ${C_WARN}--train-offline${C_RESET} -e 10 -r mix                 \033[90m# Train PPO on blended trace\033[0m"
    echo -e "  ./run_experiments.sh ${C_SUCCESS}unpatched${C_RESET} ${C_WARN}--simulate-all${C_RESET} -o -n                      \033[90m# Run ONNX sweep without core locking\033[0m"
    exit 1
}

# ── EARLY ROUTING: Handle Python target to prevent argument swallowing ──────
if [ "$1" = "python" ]; then
    TARGET="python"
    ACTION=$2
    if [ -z "$ACTION" ]; then
        print_usage
    fi
    shift 2

    # Map the action string to the targeted local python script
    case "$ACTION" in
        --train-online)
            SCRIPT="scripts/train_online.py"
            ;;
        --train-offline)
            SCRIPT="scripts/train_offline.py"
            ;;
        --deploy)
            SCRIPT="scripts/serve_agent.py"
            ;;
        --verify-brain)
            SCRIPT="scripts/verify_brain.py"
            ;;
        --export-onnx)
            SCRIPT="scripts/export_onnx.py"
            ;;
        --plot)
            # Plot engine is in the tools folder
            SCRIPT="../plot_engine.py"
            ;;
        *)
            print_usage
            ;;
    esac

    # Resolve local python executable inside virtualenv
    PYTHON_EXEC="${ROOT_DIR}/tools/rl_bridge/venv/bin/python3"
    if [ ! -f "$PYTHON_EXEC" ]; then PYTHON_EXEC="python3"; fi

    # Launch python script and pass remaining arguments untouched
    exec "$PYTHON_EXEC" "${ROOT_DIR}/tools/rl_bridge/${SCRIPT}" "$@"
fi

# ── C++ SIMULATION TARGET ARGUMENT PARSING ───────────────────────────────────
TARGET=$1
ACTION=$2

if [ -z "$TARGET" ] || { [ "$TARGET" != "unpatched" ] && [ "$TARGET" != "patched" ] && [ "$TARGET" != "all" ]; } || [ -z "$ACTION" ]; then
    print_usage
fi

shift 2

# Initialize baseline default states and matrix parameters
PIN_CORE=${PIN_CORE:-9}
USE_TASKSET=true
TOTAL_PACKETS=1000000
RUN_FILTER_OFF=true
RUN_FILTER_ON=true
RUN_ONNX=false
ONNX_MODEL_PATH=""
DISABLE_SAFETY=false

# Default global state machine mode and pollution density spectrum arrays
DEFAULT_MODES=(0 1 2)
TARGET_MODES=("${DEFAULT_MODES[@]}")

DEFAULT_RATES=(1.0 5.0 10.0)
POLLUTION_RATES=("${DEFAULT_RATES[@]}")

# Loop through C++ specific arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--core)
            if [[ -n "$2" && "$2" =~ ^[0-9]+$ ]]; then
                PIN_CORE="$2"
                shift 2
            else
                echo -e "${C_ERROR}[ERROR] -c/--core demands a valid numeric CPU index value.${C_RESET}"
                exit 1
            fi
            ;;
        -n|--no-taskset|--no-pin)
            USE_TASKSET=false
            shift
            ;;
        -B|--baseline-only|--no-filter-only)
            RUN_FILTER_OFF=true
            RUN_FILTER_ON=false
            shift
            ;;
        -F|--filter-only)
            RUN_FILTER_OFF=false
            RUN_FILTER_ON=true
            shift
            ;;
        -m|--modes)
            if [[ -n "$2" ]]; then
                IFS=' ' read -r -a TARGET_MODES <<< "$2"
                shift 2
            else
                echo -e "${C_ERROR}[ERROR] -m/--modes demands a space-separated string of integers (e.g. \"0 1\").${C_RESET}"
                exit 1
            fi
            ;;
        -r|--rates|--rate)
            if [[ -n "$2" ]]; then
                # Safe Boundary Check: "mix" is invalid for C++ targets
                if [[ "$2" == *"mix"* ]]; then
                    echo -e "${C_ERROR}[ERROR] C++ simulation targets only accept numeric rates (e.g., \"1.0 5.0\").${C_RESET}"
                    echo -e "${C_WARN}[NOTICE] \"mix\" is reserved for python --train-offline offline dataset blending.${C_RESET}"
                    exit 1
                fi
                IFS=' ' read -r -a POLLUTION_RATES <<< "$2"
                shift 2
            else
                echo -e "${C_ERROR}[ERROR] -r/--rates demands a space-separated string of numbers.${C_RESET}"
                exit 1
            fi
            ;;
        -o|--onnx)
            RUN_ONNX=true
            if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                ONNX_MODEL_PATH="$2"
                shift 2
            else
                ONNX_MODEL_PATH="${ROOT_DIR}/checkpoints/v2x_ppo_agent.onnx"
                shift
            fi
            ;;
        -s|--disable-safety)
            DISABLE_SAFETY=true
            shift
            ;;
        *)
            echo -e "${C_ERROR}[ERROR] Unknown option: $1${C_RESET}"
            exit 1
            ;;
    esac
done

# If ONNX mode is enabled, verify that the ONNX model file exists before execution
if [ "$RUN_ONNX" = true ]; then
    if [ ! -f "$ONNX_MODEL_PATH" ]; then
        echo -e "${C_ERROR}[ERROR] ONNX model file not found at: ${ONNX_MODEL_PATH}${C_RESET}"
        echo -e "${C_WARN}[NOTICE] Please make sure to compile and export the DRL model to ONNX format first.${C_RESET}"
        echo -e "${C_INFO}[INFO] Gracefully exiting.${C_RESET}"
        exit 0
    fi
fi

# Helper execution engine bypassing taskset if USE_TASKSET is set to false
execute_cmd() {
    if [ "$USE_TASKSET" = true ]; then
        taskset -c "$PIN_CORE" "$@"
    else
        "$@"
    fi
}

# Resolve lock status representation for console logs
get_core_info() {
    if [ "$USE_TASKSET" = true ]; then
        echo "Core: ${PIN_CORE}"
    else
        echo "Core: Dynamic (OS-scheduled)"
    fi
}

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
    echo -e "${C_INFO}[STAGE] Task Lock Active: Target=${tgt} | Mode=3 (Grand Mix Scenario) | Automation Flags=--rl ($(get_core_info))${C_RESET}"

    # Sequentially iterate through configuration sweeps to feed interactive socket state-spaces
    for rate in "${POLLUTION_RATES[@]}"; do
        echo -e "${C_INFO}[EXEC] Pushing dynamic training trace trajectory at rate: ${rate}%...${C_RESET}"
        local train_args=("-t" "$TOTAL_PACKETS" "-p" "$rate" "-m" 3 "--rl")
        if [ "$DISABLE_SAFETY" = true ]; then
            train_args+=("--disable-safety")
        fi
        execute_cmd "$exec_bin" "${train_args[@]}"
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
                echo -e "${C_INFO}[STAGE] Node Init: Target=${tgt} | Rate=${rate}% | Mode=${mode} | Filter=OFF ($(get_core_info))${C_RESET}"
                execute_cmd "$exec_bin" -t $TOTAL_PACKETS -p "$rate" -m "$mode"
            fi

            # Conditionally execute the circuit-breaker state-machine hardened flow node
            if [ "$RUN_FILTER_ON" = true ]; then
                echo -e "${C_INFO}[STAGE] Node Init: Target=${tgt} | Rate=${rate}% | Mode=${mode} | Filter=ON  ($(get_core_info))${C_RESET}"
                local sweep_args=("-t" "$TOTAL_PACKETS" "-p" "$rate" "-m" "$mode" "-f")
                if [ "$RUN_ONNX" = true ]; then
                    sweep_args+=("--onnx" "$ONNX_MODEL_PATH")
                fi
                if [ "$DISABLE_SAFETY" = true ]; then
                    sweep_args+=("--disable-safety")
                fi
                execute_cmd "$exec_bin" "${sweep_args[@]}"
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
            
            echo -e "${C_INFO}[INFO] Triggering dedicated framework routine: ${ACTION} on target [${tgt}] ($(get_core_info))${C_RESET}"
            execute_cmd "$bin" "$ACTION"
            
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
        
        CUSTOM_ARGS=("$@")
        if [ "$RUN_ONNX" = true ]; then
            CUSTOM_ARGS+=("--onnx" "$ONNX_MODEL_PATH")
        fi
        if [ "$DISABLE_SAFETY" = true ]; then
            CUSTOM_ARGS+=("--disable-safety")
        fi
        
        echo -e "${C_INFO}[INFO] Invoking custom framework map... Args: ${CUSTOM_ARGS[*]}${C_RESET}"
        EXEC_BIN="${ROOT_DIR}/vanetza_${TARGET}/build/bin/qos-harness"
        execute_cmd "$EXEC_BIN" "${CUSTOM_ARGS[@]}"
        ;;
        
    *)
        print_usage
        ;;
esac