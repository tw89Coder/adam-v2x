#!/bin/bash

# ==============================================================================
# Vanetza Environment Setup & Compilation Orchestrator
# ==============================================================================
# This script automates dependency verification, smart package installation,
# patch management, and CMake-based compilation for the Vanetza protocol library.
#
# Supported Systems: Ubuntu / Debian
# Naming Standards: PEP8/Google Style for Bash variables and functions
# ==============================================================================

# Exit immediately if any command fails, undefined variables are referenced,
# or any command in a pipeline fails.
set -euo pipefail

# Define output color formatting constants
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_RED='\033[0;31m'
readonly COLOR_NC='\033[0m' # No Color

# ------------------------------------------------------------------------------
# Logging Utilities
# ------------------------------------------------------------------------------

log_success() {
    echo -e "${COLOR_GREEN}[SUCCESS] $1${COLOR_NC}"
}

log_warning() {
    echo -e "${COLOR_YELLOW}[WARNING] $1${COLOR_NC}"
}

log_error() {
    echo -e "${COLOR_RED}[ERROR] $1${COLOR_NC}" >&2
}

# ------------------------------------------------------------------------------
# Version Comparison Helper
# ------------------------------------------------------------------------------

# Compare two semantic versions ($1 >= $2)
# Returns 0 (true) if version $1 is greater than or equal to $2, otherwise 1 (false).
version_ge() {
    local ver1="$1"
    local ver2="$2"
    [ "$(printf '%s\n%s' "$ver2" "$ver1" | sort -V | head -n1)" = "$ver2" ]
}

# ------------------------------------------------------------------------------
# Dependency Version Resolution Functions
# ------------------------------------------------------------------------------

# Get installed C++ compiler version (GCC or Clang)
get_compiler_version() {
    if command -v g++ >/dev/null 2>&1; then
        g++ -dumpfullversion -dumpversion 2>/dev/null || g++ -dumpversion 2>/dev/null || echo "0"
    elif command -v clang++ >/dev/null 2>&1; then
        clang++ --version | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "0"
    else
        echo "0"
    fi
}

# Get installed CMake version
get_cmake_version() {
    if command -v cmake >/dev/null 2>&1; then
        cmake --version | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "0"
    else
        echo "0"
    fi
}

# Get installed Boost version (parses headers or queries dpkg)
get_boost_version() {
    if [ -f "/usr/include/boost/version.hpp" ]; then
        local version_str
        version_str=$(grep -E '#define BOOST_LIB_VERSION' /usr/include/boost/version.hpp | grep -oE '[0-9]+_[0-9]+(_[0-9]+)?' | tr '_' '.' || true)
        if [ -n "$version_str" ]; then
            echo "$version_str"
            return
        fi
    fi
    local dpkg_ver
    dpkg_ver=$(dpkg-query -W -f='${Version}' libboost-dev 2>/dev/null | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' || true)
    if [ -n "$dpkg_ver" ]; then
        echo "$dpkg_ver"
    else
        echo "0"
    fi
}

# Get installed GeographicLib version
get_geographic_version() {
    if pkg-config --exists geographiclib 2>/dev/null; then
        pkg-config --modversion geographiclib 2>/dev/null
    elif [ -f "/usr/include/GeographicLib/Config.h" ]; then
        grep -E '#define GEOGRAPHICLIB_VERSION_STRING' /usr/include/GeographicLib/Config.h | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' || echo "0"
    else
        local dpkg_ver
        dpkg_ver=$(dpkg-query -W -f='${Version}' libgeographic-dev 2>/dev/null | grep -oE '^[0-9]+\.[0-9]+(\.[0-9]+)?' || true)
        if [ -n "$dpkg_ver" ]; then
            echo "$dpkg_ver"
        else
            echo "0"
        fi
    fi
}

# Get installed Crypto++ version
get_cryptopp_version() {
    if pkg-config --exists libcrypto++ 2>/dev/null; then
        pkg-config --modversion libcrypto++ 2>/dev/null
    elif [ -f "/usr/include/cryptopp/config.h" ]; then
        local raw_ver
        raw_ver=$(grep -E '#define CRYPTOPP_VERSION' /usr/include/cryptopp/config.h | grep -oE '[0-9]+' || true)
        if [ -n "$raw_ver" ]; then
            local major=${raw_ver:0:1}
            local minor=${raw_ver:1:1}
            local patch=${raw_ver:2:1}
            patch=${patch:-0}
            echo "${major}.${minor}.${patch}"
            return
        fi
    fi
    local dpkg_ver
    dpkg_ver=$(dpkg-query -W -f='${Version}' libcrypto++-dev 2>/dev/null | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' || true)
    if [ -n "$dpkg_ver" ]; then
        echo "$dpkg_ver"
    else
        echo "0"
    fi
}

# Get installed OpenSSL version
get_openssl_version() {
    if command -v openssl >/dev/null 2>&1; then
        openssl version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[a-z]?' | head -n1 || echo "0"
    else
        echo "0"
    fi
}

# ------------------------------------------------------------------------------
# Main Orchestration Logic
# ------------------------------------------------------------------------------

# Define minimum version requirements
readonly REQ_COMPILER_GCC="4.8.0"
readonly REQ_CMAKE="3.12.0"
readonly REQ_BOOST="1.58.0"
readonly REQ_GEOGRAPHIC="1.37.0"
readonly REQ_CRYPTOPP="5.6.1"

# List to aggregate missing APT packages
missing_packages=()

print_usage() {
    echo "Usage: $0 [patch|unpatch|all]"
    echo ""
    echo "Modes:"
    echo "  patch      Validate dependencies, apply project patches, and compile the patched library."
    echo "  unpatch    Validate dependencies, revert patches (original codebase), and compile the unpatched library."
    echo "  all        Validate dependencies, then build both patched and unpatched libraries sequentially."
}

# Ensure command line arguments are present and valid
if [ $# -ne 1 ]; then
    log_error "Invalid number of arguments."
    print_usage
    exit 1
fi

readonly MODE="$1"
if [ "$MODE" != "patch" ] && [ "$MODE" != "unpatch" ] && [ "$MODE" != "all" ]; then
    log_error "Unknown mode: '${MODE}'"
    print_usage
    exit 1
fi

echo "======================================================================"
echo "[*] Step 1: Starting Smart Prerequisites Check..."
echo "======================================================================"

# 1. Check C++11 Compiler (GCC / Clang)
compiler_ver=$(get_compiler_version)
if [ "$compiler_ver" != "0" ] && version_ge "$compiler_ver" "$REQ_COMPILER_GCC"; then
    log_success "Compiler found: version ${compiler_ver} (supports C++11)"
else
    log_warning "C++11 compatible compiler not found or insufficient version (${compiler_ver} < ${REQ_COMPILER_GCC})."
    missing_packages+=("build-essential" "g++")
fi

# 2. Check CMake
cmake_ver=$(get_cmake_version)
if [ "$cmake_ver" != "0" ] && version_ge "$cmake_ver" "$REQ_CMAKE"; then
    log_success "CMake found: version ${cmake_ver} (>= ${REQ_CMAKE})"
else
    log_warning "CMake not found or insufficient version (${cmake_ver} < ${REQ_CMAKE})."
    missing_packages+=("cmake")
fi

# 3. Check Boost
boost_ver=$(get_boost_version)
if [ "$boost_ver" != "0" ] && version_ge "$boost_ver" "$REQ_BOOST"; then
    log_success "Boost found: version ${boost_ver} (>= ${REQ_BOOST})"
else
    log_warning "Boost not found or insufficient version (${boost_ver} < ${REQ_BOOST})."
    missing_packages+=("libboost-dev" "libboost-all-dev")
fi

# 4. Check GeographicLib
geo_ver=$(get_geographic_version)
if [ "$geo_ver" != "0" ] && version_ge "$geo_ver" "$REQ_GEOGRAPHIC"; then
    log_success "GeographicLib found: version ${geo_ver} (>= ${REQ_GEOGRAPHIC})"
else
    log_warning "GeographicLib not found or insufficient version (${geo_ver} < ${REQ_GEOGRAPHIC})."
    missing_packages+=("libgeographic-dev")
fi

# 5. Check Crypto++
crypto_ver=$(get_cryptopp_version)
if [ "$crypto_ver" != "0" ] && version_ge "$crypto_ver" "$REQ_CRYPTOPP"; then
    log_success "Crypto++ found: version ${crypto_ver} (>= ${REQ_CRYPTOPP})"
else
    log_warning "Crypto++ not found or insufficient version (${crypto_ver} < ${REQ_CRYPTOPP})."
    missing_packages+=("libcrypto++-dev")
fi

# 6. Check OpenSSL (Optional backend)
openssl_ver=$(get_openssl_version)
if [ "$openssl_ver" != "0" ]; then
    log_success "OpenSSL found: version ${openssl_ver}"
else
    log_warning "OpenSSL not found. Marking optional package 'libssl-dev' for installation."
    missing_packages+=("libssl-dev" "openssl")
fi

# ------------------------------------------------------------------------------
# Install Missing Dependencies
# ------------------------------------------------------------------------------
if [ ${#missing_packages[@]} -gt 0 ]; then
    log_warning "The following required dependencies are missing or outdated: ${missing_packages[*]}"
    echo "[*] Requesting root privileges to install missing packages..."
    
    # Check if apt-get is available
    if ! command -v apt-get >/dev/null 2>&1; then
        log_error "apt-get package manager not found. Please install the dependencies manually."
        exit 1
    fi
    
    sudo apt-get update
    sudo apt-get install -y "${missing_packages[@]}"
    log_success "Prerequisites successfully installed via package manager."
else
    log_success "All prerequisites are satisfied. Skipping dependency installation."
fi

# Get the script directory as the root path
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ------------------------------------------------------------------------------
# Action Helper Functions
# ------------------------------------------------------------------------------

apply_patches() {
    local target_dir="$1"
    echo "[*] Preparing workspace at ${target_dir}..."
    
    # ==========================================
    # TODO / PLACEHOLDER: Insert patch commands
    # ==========================================
    # Add your custom patch applications here.
    # E.g., patch -p1 < custom_mitigation.patch
    # ==========================================
    log_warning "TODO: Insert custom patch application commands in this block."
    # ==========================================
    
    log_success "Patch configuration successfully applied."
}

revert_patches() {
    local target_dir="$1"
    echo "[*] Preparing workspace at ${target_dir}..."
    
    # ==========================================
    # TODO / PLACEHOLDER: Insert unpatch commands
    # ==========================================
    # Add your commands to revert/remove patches.
    # E.g., patch -R -p1 < custom_mitigation.patch
    # ==========================================
    log_warning "TODO: Insert custom patch reversion commands in this block."
    # ==========================================
    
    log_success "Patch configuration successfully reverted."
}

compile_library() {
    local target_dir="$1"
    local mode_name="$2"
    echo "======================================================================"
    echo "[*] Compiling Vanetza Library at ${target_dir}..."
    echo "======================================================================"

    if [ ! -d "$target_dir" ]; then
        log_error "Target directory does not exist: ${target_dir}"
        exit 1
    fi

    local build_dir="${target_dir}/build"
    mkdir -p "$build_dir"
    cd "$build_dir"

    echo "[*] Running CMake configuration..."
    cmake ..

    local cores=$(nproc)
    echo "[*] Starting compilation on ${cores} CPU cores..."
    make -j"${cores}"

    log_success "Vanetza library compilation complete in ${mode_name} mode."
    echo "======================================================================"
}

# ------------------------------------------------------------------------------
# Run Requested Actions
# ------------------------------------------------------------------------------

if [ "$MODE" == "patch" ]; then
    echo "======================================================================"
    echo "[*] Step 2: Processing Patch Configuration..."
    echo "======================================================================"
    apply_patches "${SCRIPT_DIR}/vanetza_patched"
    compile_library "${SCRIPT_DIR}/vanetza_patched" "patch"

elif [ "$MODE" == "unpatch" ]; then
    echo "======================================================================"
    echo "[*] Step 2: Processing Patch Configuration..."
    echo "======================================================================"
    revert_patches "${SCRIPT_DIR}/vanetza_unpatched"
    compile_library "${SCRIPT_DIR}/vanetza_unpatched" "unpatch"

elif [ "$MODE" == "all" ]; then
    echo "======================================================================"
    echo "[*] Step 2: Processing Patch Configuration for 'unpatch'..."
    echo "======================================================================"
    revert_patches "${SCRIPT_DIR}/vanetza_unpatched"
    compile_library "${SCRIPT_DIR}/vanetza_unpatched" "unpatch"

    echo "======================================================================"
    echo "[*] Step 3: Processing Patch Configuration for 'patch'..."
    echo "======================================================================"
    apply_patches "${SCRIPT_DIR}/vanetza_patched"
    compile_library "${SCRIPT_DIR}/vanetza_patched" "patch"
fi
