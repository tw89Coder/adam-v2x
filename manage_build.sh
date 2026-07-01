#!/bin/bash

# ==============================================================================
# V2X QoS Harness Compilation and Build Automation Framework
# ==============================================================================

# Halt execution instantly if any standalone pipeline instruction fails
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NUM_CORES=$(nproc)

# ------------------------------------------------------------------------------
# Decoupled ANSI Color Escape Sequences (Consistent with run_experiments.sh)
# ------------------------------------------------------------------------------
ANSI_RESET="\033[0m"
ANSI_BOLD="\033[1m"
ANSI_CYAN="\033[1;36m"
ANSI_GREEN="\033[1;32m"
ANSI_YELLOW="\033[1;33m"
ANSI_RED="\033[1;31m"
ANSI_BLUE="\033[1;34m"

# ------------------------------------------------------------------------------
# Semantic Color Mapping
# ------------------------------------------------------------------------------
COLOR_RESET="${ANSI_RESET}"
COLOR_BOLD="${ANSI_BOLD}"
COLOR_INFO="${ANSI_CYAN}"
COLOR_SUCCESS="${ANSI_GREEN}"
COLOR_WARNING="${ANSI_YELLOW}"
COLOR_DANGER="${ANSI_RED}"
COLOR_PRIMARY="${ANSI_BLUE}"

# ------------------------------------------------------------------------------
# Logging Utilities (For banners & fast unformatted logs)
# ------------------------------------------------------------------------------

# @description Print a message in Primary semantic color (Bold Blue).
# @param $1 string The message to be printed.
log_primary() {
    echo -e "${COLOR_PRIMARY}${1}${COLOR_RESET}"
}

# @description Prints script usage guidelines and exit codes with inline highlighting.
# @exit-code 1 If arguments are invalid or missing.
print_usage() {
    echo -e "${COLOR_INFO}Usage:${COLOR_RESET} ./manage_build.sh ${COLOR_SUCCESS}[target]${COLOR_RESET} ${COLOR_WARNING}[mode]${COLOR_RESET}"
    echo -e "       ./manage_build.sh ${COLOR_SUCCESS}--sync-harness${COLOR_RESET} ${COLOR_WARNING}[--reverse]${COLOR_RESET}"
    echo -e ""
    echo -e "${COLOR_BOLD}Targets:${COLOR_RESET}"
    echo -e "  ${COLOR_SUCCESS}unpatched${COLOR_RESET}      Build the vulnerable/unpatched Vanetza stack workspace"
    echo -e "  ${COLOR_SUCCESS}patched${COLOR_RESET}        Build the secured/patched state-machine Vanetza workspace"
    echo -e "  ${COLOR_SUCCESS}all${COLOR_RESET}            Sequentially compile both workspaces"
    echo -e "  ${COLOR_SUCCESS}--sync-harness${COLOR_RESET} Synchronize qos-harness package between workspaces (Default: unpatched -> patched)"
    echo -e ""
    echo -e "${COLOR_BOLD}Modes:${COLOR_RESET}"
    echo -e "  ${COLOR_WARNING}fast${COLOR_RESET}           Execute incremental compilation using naked make only (Default)"
    echo -e "  ${COLOR_WARNING}clean${COLOR_RESET}          Wipe active build directories entirely and re-run full CMake"
    echo -e "  ${COLOR_WARNING}--reverse${COLOR_RESET}      Used with --sync-harness to force reverse sync (patched -> unpatched)"
    exit 1
}

# @description Compiles a given V2X Vanetza workspace using cmake and make.
# @param $1 string The target workspace subdirectory name.
# @param $2 string The compile mode ('fast' or 'clean').
# @exit-code 1 If target workspace directory does not exist.
compile_workspace() {
    local workspace=$1
    local mode=$2
    local ws_path="${ROOT_DIR}/${workspace}"
    local build_path="${ws_path}/build"

    log_primary "======================================================================"
    echo -e "${COLOR_PRIMARY}[*] Initializing Pipeline Target:${COLOR_RESET} ${COLOR_SUCCESS}${workspace}${COLOR_RESET} (${COLOR_WARNING}${mode}${COLOR_RESET} mode)"
    log_primary "======================================================================"

    if [ ! -d "$ws_path" ]; then
        echo -e "${COLOR_DANGER}[ERROR] Target directory workspace folder ${ws_path} does not exist.${COLOR_RESET}"
        exit 1
    fi

    if [ "$mode" == "clean" ]; then
        echo -e "${COLOR_WARNING}[CLEAN] Purging legacy caches and stale binaries under${COLOR_RESET} ${COLOR_INFO}${build_path}${COLOR_RESET}..."
        rm -rf "$build_path"
    fi

    mkdir -p "$build_path"
    cd "$build_path"

    if [ "$mode" == "clean" ] || [ ! -f "Makefile" ]; then
        echo -e "${COLOR_INFO}[CMAKE] Structuring clean dependency maps via CMake...${COLOR_RESET}"
        cmake ..
    fi

    echo -e "${COLOR_INFO}[MAKE] Launching parallel hardware compilation utilizing${COLOR_RESET} ${COLOR_SUCCESS}${NUM_CORES}${COLOR_RESET} ${COLOR_INFO}cores...${COLOR_RESET}"
    make -j"${NUM_CORES}"
    
    echo -e "${COLOR_SUCCESS}[SUCCESS] Workspace compilation successfully complete:${COLOR_RESET} ${COLOR_SUCCESS}${workspace}${COLOR_RESET}"
    cd "$ROOT_DIR"
}

# @description Syncs the qos-harness codebase dynamically between unpatched and patched workspaces.
# @param $1 string Optional modifier ('--reverse' to force patched -> unpatched).
sync_harness() {
    local reverse_direction=false
    if [ "${1:-}" == "--reverse" ]; then
        reverse_direction=true
    fi

    local src_dir=""
    local dest_dir=""

    if [ "$reverse_direction" = true ]; then
        src_dir="${ROOT_DIR}/vanetza_patched/tools/qos-harness"
        dest_dir="${ROOT_DIR}/vanetza_unpatched/tools/qos-harness"
        echo -e "${COLOR_DANGER}[CAUTION] REVERSE SYNCHRONIZATION DETECTED!${COLOR_RESET}"
        echo -e "Direction: ${COLOR_WARNING}patched${COLOR_RESET} (source) ---> ${COLOR_DANGER}unpatched${COLOR_RESET} (destination)"
        echo -e "Warning: This will overwrite files in the unpatched harness folder with patched harness code."
    else
        src_dir="${ROOT_DIR}/vanetza_unpatched/tools/qos-harness"
        dest_dir="${ROOT_DIR}/vanetza_patched/tools/qos-harness"
        echo -e "${COLOR_WARNING}[WARNING] HARNESS SYNCHRONIZATION ROUTINE${COLOR_RESET}"
        echo -e "Direction: ${COLOR_SUCCESS}unpatched${COLOR_RESET} (source) ---> ${COLOR_WARNING}patched${COLOR_RESET} (destination)"
        echo -e "Action: This will sync latest ONNX / safety configurations to the patched workspace."
    fi

    # Verify source directory exists
    if [ ! -d "$src_dir" ]; then
        echo -e "${COLOR_DANGER}[ERROR] Source directory does not exist: ${src_dir}${COLOR_RESET}" >&2
        exit 1
    fi

    # Verify stdin is a terminal for safety prompt
    if [ -t 0 ]; then
        read -p "Are you absolutely sure you want to proceed with this synchronization? (y/N): " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo -e "${COLOR_WARNING}[CANCELLED] Synchronization aborted by user.${COLOR_RESET}"
            exit 0
        fi
    else
        echo -e "${COLOR_DANGER}[ERROR] Non-interactive environment detected. Synchronization requires interactive terminal confirmation.${COLOR_RESET}" >&2
        exit 1
    fi

    echo -e "${COLOR_INFO}[*] Syncing directories...${COLOR_RESET}"

    # Use rsync if available, otherwise fallback to cp -r
    if command -v rsync >/dev/null 2>&1; then
        rsync -av --delete --exclude="build" --exclude="CMakeFiles" --exclude="cmake_install.cmake" --exclude="Makefile" "$src_dir/" "$dest_dir/"
    else
        echo -e "${COLOR_WARNING}[WARNING] rsync not found. Falling back to cp/rm...${COLOR_RESET}"
        mkdir -p "$dest_dir"
        rm -rf "${dest_dir:?}/"*
        cp -r "$src_dir/"* "$dest_dir/"
    fi

    echo -e "${COLOR_SUCCESS}[SUCCESS] Harness synchronization complete!${COLOR_RESET}"
}

# Intercept sync-harness command before normal target checks
if [ "${1:-}" == "--sync-harness" ]; then
    sync_harness "${2:-}"
    exit 0
fi

# Parse basic terminal boundary input tokens
TARGET=$1
MODE=${2:-fast}

if [ -z "$TARGET" ] || { [ "$TARGET" != "unpatched" ] && [ "$TARGET" != "patched" ] && [ "$TARGET" != "all" ]; } || { [ "$MODE" != "fast" ] && [ "$MODE" != "clean" ]; }; then
    print_usage
fi

if [ "$TARGET" == "all" ]; then
    compile_workspace "vanetza_unpatched" "$MODE"
    compile_workspace "vanetza_patched" "$MODE"
else
    compile_workspace "vanetza_${TARGET}" "$MODE"
fi

log_primary "======================================================================"
echo -e "${COLOR_SUCCESS}[SUCCESS] Build workflow successfully verified. System updated.${COLOR_RESET}"
log_primary "======================================================================"