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
    echo -e "  ${C_WARN}--test${C_RESET}               Run python strategy consistency unit tests via pytest"
    echo -e "  ${C_INFO}  * Tip: Append -h/--help to any python action to view its specific parameters${C_RESET}"
    echo -e "    (e.g., ./run_experiments.sh python --train-online -h)"
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
        --test|--run-tests)
            # Unified testing entry point executing consistency checks via pytest
            PYTHON_EXEC="${ROOT_DIR}/tools/rl_bridge/venv/bin/python3"
            if [ ! -f "$PYTHON_EXEC" ]; then PYTHON_EXEC="python3"; fi
            
            if "$PYTHON_EXEC" -c "import pytest" &>/dev/null; then
                echo -e "${C_INFO}[*] Running consistency tests via pytest...${C_RESET}"
                exec "$PYTHON_EXEC" -m pytest "${ROOT_DIR}/tools/rl_bridge/tests/test_consistency.py" "$@"
            else
                echo -e "${C_ERROR}[ERROR] pytest is not installed in the virtual environment.${C_RESET}"
                echo -e "${C_WARN}[SUGGESTION] Please install it using: tools/rl_bridge/venv/bin/pip install pytest${C_RESET}"
                exit 1
            fi
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
RUN_TRACE=false


# Chi-AN : experiment data flow control  parameters 

ZIP_MODE=false
SEQUENCE_FILE=""
DRY_RUN=false

# Default global state machine mode and pollution density spectrum arrays
DEFAULT_MODES=(0 1 2)
TARGET_MODES=("${DEFAULT_MODES[@]}")

DEFAULT_RATES=(1.0 5.0 10.0)
POLLUTION_RATES=("${DEFAULT_RATES[@]}")

# Loop through C++ specific arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|-T|--trace)
            RUN_TRACE=true
            shift
            ;;
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
                # If only a filename is provided (no slashes), search in the default checkpoints directory
                if [[ "$ONNX_MODEL_PATH" != *"/"* ]]; then
                    ONNX_MODEL_PATH="${ROOT_DIR}/checkpoints/${ONNX_MODEL_PATH}"
                fi
                shift 2
            else
                # Dynamically extract default algorithm from agent.yaml
                ALGO_NAME=$(grep -E '^algorithm:' "${ROOT_DIR}/tools/rl_bridge/config/agent.yaml" | awk '{print $2}' | tr -d '"' | tr -d "'" | tr -d '\r')
                if [[ -z "$ALGO_NAME" ]]; then
                    ALGO_NAME="dqn"
                fi
                ONNX_MODEL_PATH="${ROOT_DIR}/checkpoints/v2x_agent_${ALGO_NAME}.onnx"
                shift
            fi
            ;;
        -s|--disable-safety)
            DISABLE_SAFETY=true
            shift
            ;;
        #===================================Chi-AN: new command for training data flow =======================================
        --zip|--paired)
            ZIP_MODE=true
            shift
            ;;

        --sequence-file|--seq-file)
            if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                SEQUENCE_FILE="$2"
                shift 2
            else
                echo -e "${C_ERROR}[ERROR] --sequence-file demands a file path.${C_RESET}"
                exit 1
            fi
            ;;

        --dry-run)
            DRY_RUN=true
            shift
            ;;

        -N|--packets)
            if [[ -n "$2" && "$2" =~ ^[0-9]+$ ]]; then
                TOTAL_PACKETS="$2"
                shift 2
            else
                echo -e "${C_ERROR}[ERROR] -N/--packets demands a positive integer.${C_RESET}"
                exit 1
            fi
            ;;
        *)
            echo -e "${C_ERROR}[ERROR] Unknown option: $1${C_RESET}"
            exit 1
            ;;
    esac
done

# Verify mutual exclusivity: ONNX mode (-o/--onnx) demands the FSM filter to be active
if [ "$RUN_ONNX" = true ] && [ "$RUN_FILTER_ON" = false ]; then
    echo -e "${C_ERROR}[ERROR] Conflict: ONNX mode (-o/--onnx) and Baseline-Only (-B) are mutually exclusive.${C_RESET}"
    echo -e "${C_WARN}[NOTICE] ONNX inference requires the pre-filter to be active, but -B disables filtering.${C_RESET}"
    exit 1
fi

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

# ===============Chi-AN: new function for training data flow control ==========================================
run_training_pair() {
    local tgt="$1"
    local exec_bin="$2"
    local mode="$3"
    local rate="$4"

    echo -e "${C_INFO}[EXEC] RL trajectory: target=${tgt}, mode=${mode}, rate=${rate}%, packets=${TOTAL_PACKETS}${C_RESET}"

    local train_args=("-t" "$TOTAL_PACKETS" "-p" "$rate" "-m" "$mode" "--rl")

    if [ "$DISABLE_SAFETY" = true ]; then
        train_args+=("--disable-safety")
    fi

    if [ "$DRY_RUN" = true ]; then
        echo -e "${C_WARN}[DRY-RUN] $exec_bin ${train_args[*]}${C_RESET}"
    else
        execute_cmd "$exec_bin" "${train_args[@]}"
    fi

    echo "----------------------------------------------------------------------"
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

    mkdir -p "${ROOT_DIR}/outputs/rl_env"

    echo -e "${C_INFO}[STAGE] RL Training | Target=${tgt} | Packets=${TOTAL_PACKETS} | Core=$(get_core_info)${C_RESET}"

    # Priority 1: read explicit sequence file
    if [ -n "$SEQUENCE_FILE" ]; then
        if [ ! -f "$SEQUENCE_FILE" ]; then
            echo -e "${C_ERROR}[ERROR] Sequence file not found: ${SEQUENCE_FILE}${C_RESET}"
            exit 1
        fi

        echo -e "${C_INFO}[MODE] Using sequence file: ${SEQUENCE_FILE}${C_RESET}"

        local line_no=0
        while read -r mode rate extra; do
            line_no=$((line_no + 1))

            # Skip empty lines and comments
            [[ -z "$mode" ]] && continue
            [[ "$mode" =~ ^# ]] && continue

            if [[ -z "$rate" ]]; then
                echo -e "${C_ERROR}[ERROR] Invalid sequence line ${line_no}: missing rate.${C_RESET}"
                exit 1
            fi

            if [[ -n "$extra" ]]; then
                echo -e "${C_WARN}[WARN] Extra tokens ignored at line ${line_no}: ${extra}${C_RESET}"
            fi

            run_training_pair "$tgt" "$exec_bin" "$mode" "$rate"
        done < "$SEQUENCE_FILE"

        return
    fi

    # Priority 2: paired arrays
    if [ "$ZIP_MODE" = true ]; then
        echo -e "${C_INFO}[MODE] Using zipped mode/rate arrays.${C_RESET}"

        if [ "${#TARGET_MODES[@]}" -ne "${#POLLUTION_RATES[@]}" ]; then
            echo -e "${C_ERROR}[ERROR] --zip requires the number of modes and rates to match.${C_RESET}"
            echo -e "${C_ERROR}[ERROR] modes=${#TARGET_MODES[@]}, rates=${#POLLUTION_RATES[@]}${C_RESET}"
            exit 1
        fi

        for i in "${!TARGET_MODES[@]}"; do
            run_training_pair "$tgt" "$exec_bin" "${TARGET_MODES[$i]}" "${POLLUTION_RATES[$i]}"
        done

        return
    fi

    # Priority 3: original matrix behavior
    echo -e "${C_INFO}[MODE] Using matrix sweep: modes x rates.${C_RESET}"

    for mode in "${TARGET_MODES[@]}"; do
        for rate in "${POLLUTION_RATES[@]}"; do
            run_training_pair "$tgt" "$exec_bin" "$mode" "$rate"
        done
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
                echo -e "${C_INFO}[STAGE] Node Init: Target=${tgt} | Rate=${rate}% | Mode=${mode} | Filter=OFF | ONNX=OFF ($(get_core_info))${C_RESET}"
                execute_cmd "$exec_bin" -t $TOTAL_PACKETS -p "$rate" -m "$mode"
            fi

            # Conditionally execute the circuit-breaker state-machine hardened flow node
            if [ "$RUN_FILTER_ON" = true ]; then
                local onnx_status="OFF"; if [ "$RUN_ONNX" = true ]; then onnx_status="ON"; fi
                echo -e "${C_INFO}[STAGE] Node Init: Target=${tgt} | Rate=${rate}% | Mode=${mode} | Filter=ON  | ONNX=${onnx_status} ($(get_core_info))${C_RESET}"
                local sweep_args=("-t" "$TOTAL_PACKETS" "-p" "$rate" "-m" "$mode" "-f")
                if [ "$RUN_ONNX" = true ]; then
                    sweep_args+=("--onnx" "$ONNX_MODEL_PATH")
                fi
                if [ "$DISABLE_SAFETY" = true ]; then
                    sweep_args+=("--disable-safety")
                fi
                if [ "$RUN_TRACE" = true ]; then
                    sweep_args+=("--trace")
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