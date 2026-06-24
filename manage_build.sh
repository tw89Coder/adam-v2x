#!/bin/bash

# ==============================================================================
# V2X QoS Harness Compilation and Build Automation Framework
# ==============================================================================

# Halt execution instantly if any standalone pipeline instruction fails
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NUM_CORES=$(nproc)

print_usage() {
    echo "Usage: ./manage_build.sh [target] [mode]"
    echo "Targets:"
    echo "  unpatched   Build the vulnerable/unpatched Vanetza stack workspace"
    echo "  patched     Build the secured/patched state-machine Vanetza workspace"
    echo "  all         Sequentially compile both workspaces"
    echo "Modes:"
    echo "  fast        Execute incremental compilation using naked make only (Default)"
    echo "  clean       Wipe active build directories entirely and re-run full CMake"
    exit 1
}

compile_workspace() {
    local workspace=$1
    local mode=$2
    local ws_path="${ROOT_DIR}/${workspace}"
    local build_path="${ws_path}/build"

    echo "======================================================================"
    echo "[*] Initializing Pipeline Target: ${workspace} (${mode} mode)"
    echo "======================================================================"

    if [ ! -d "$ws_path" ]; then
        echo "[-] Error: Target directory workspace folder ${ws_path} does not exist."
        exit 1
    fi

    if [ "$mode" == "clean" ]; then
        echo "[*] Purging legacy caches and stale binaries under ${build_path}..."
        rm -rf "$build_path"
    fi

    mkdir -p "$build_path"
    cd "$build_path"

    if [ "$mode" == "clean" ] || [ ! -f "Makefile" ]; then
        echo "[*] Structuring clean dependency maps via CMake..."
        cmake ..
    fi

    echo "[*] Launching parallel hardware compilation utilizing ${NUM_CORES} cores..."
    make -j"${NUM_CORES}"
    
    echo "[+] Workspace compilation successfully complete: ${workspace}"
    cd "$ROOT_DIR"
}

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

echo "======================================================================"
echo "[+] Build workflow successfully verified. System updated."
echo "======================================================================"