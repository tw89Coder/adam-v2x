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

# ------------------------------------------------------------------------------
# Decoupled ANSI Color Escape Sequences (Consistent with run_experiments.sh)
# ------------------------------------------------------------------------------
readonly ANSI_RESET="\033[0m"
readonly ANSI_BOLD="\033[1m"
readonly ANSI_CYAN="\033[1;36m"
readonly ANSI_GREEN="\033[1;32m"
readonly ANSI_YELLOW="\033[1;33m"
readonly ANSI_RED_BG="\033[1;41;37m"
readonly ANSI_BLUE="\033[1;34m"

# ------------------------------------------------------------------------------
# Semantic Color Mapping
# ------------------------------------------------------------------------------
readonly COLOR_RESET="${ANSI_RESET}"
readonly COLOR_BOLD="${ANSI_BOLD}"
readonly COLOR_INFO="${ANSI_CYAN}"
readonly COLOR_SUCCESS="${ANSI_GREEN}"
readonly COLOR_WARNING="${ANSI_YELLOW}"
readonly COLOR_DANGER="${ANSI_RED_BG}"
readonly COLOR_PRIMARY="${ANSI_BLUE}"

# ------------------------------------------------------------------------------
# Logging Utilities
# ------------------------------------------------------------------------------

log_success() {
    echo -e "${COLOR_SUCCESS}[SUCCESS] $1${COLOR_RESET}"
}

log_warning() {
    echo -e "${COLOR_WARNING}[WARNING] $1${COLOR_RESET}"
}

log_error() {
    echo -e "${COLOR_DANGER}[ERROR] $1${COLOR_RESET}" >&2
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
    echo -e "${COLOR_INFO}Usage:${COLOR_RESET} $0 ${COLOR_SUCCESS}[patch|unpatch|all]${COLOR_RESET}"
    echo -e ""
    echo -e "${COLOR_BOLD}Modes:${COLOR_RESET}"
    echo -e "  ${COLOR_SUCCESS}patch${COLOR_RESET}      Validate dependencies, apply project patches, and compile the patched library."
    echo -e "  ${COLOR_SUCCESS}unpatch${COLOR_RESET}    Validate dependencies, revert patches (original codebase), and compile the unpatched library."
    echo -e "  ${COLOR_SUCCESS}all${COLOR_RESET}        Validate dependencies, then build both patched and unpatched libraries sequentially."
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

echo -e "${COLOR_PRIMARY}======================================================================${COLOR_RESET}"
echo -e "${COLOR_PRIMARY}[*] Step 1: Starting Smart Prerequisites Check...${COLOR_RESET}"
echo -e "${COLOR_PRIMARY}======================================================================${COLOR_RESET}"

# 1. Check C++11 Compiler (GCC / Clang)
compiler_ver=$(get_compiler_version)
if [ "$compiler_ver" != "0" ] && version_ge "$compiler_ver" "$REQ_COMPILER_GCC"; then
    echo -e "${COLOR_SUCCESS}[SUCCESS]${COLOR_RESET} Compiler found: version ${COLOR_SUCCESS}${compiler_ver}${COLOR_RESET} (supports C++11)"
else
    echo -e "${COLOR_WARNING}[WARNING]${COLOR_RESET} C++11 compatible compiler not found or insufficient version (${COLOR_WARNING}${compiler_ver}${COLOR_RESET} < ${COLOR_INFO}${REQ_COMPILER_GCC}${COLOR_RESET})."
    missing_packages+=("build-essential" "g++")
fi

# 2. Check CMake
cmake_ver=$(get_cmake_version)
if [ "$cmake_ver" != "0" ] && version_ge "$cmake_ver" "$REQ_CMAKE"; then
    echo -e "${COLOR_SUCCESS}[SUCCESS]${COLOR_RESET} CMake found: version ${COLOR_SUCCESS}${cmake_ver}${COLOR_RESET} (>= ${COLOR_INFO}${REQ_CMAKE}${COLOR_RESET})"
else
    echo -e "${COLOR_WARNING}[WARNING]${COLOR_RESET} CMake not found or insufficient version (${COLOR_WARNING}${cmake_ver}${COLOR_RESET} < ${COLOR_INFO}${REQ_CMAKE}${COLOR_RESET})."
    missing_packages+=("cmake")
fi

# 3. Check Boost
boost_ver=$(get_boost_version)
if [ "$boost_ver" != "0" ] && version_ge "$boost_ver" "$REQ_BOOST"; then
    echo -e "${COLOR_SUCCESS}[SUCCESS]${COLOR_RESET} Boost found: version ${COLOR_SUCCESS}${boost_ver}${COLOR_RESET} (>= ${COLOR_INFO}${REQ_BOOST}${COLOR_RESET})"
else
    echo -e "${COLOR_WARNING}[WARNING]${COLOR_RESET} Boost not found or insufficient version (${COLOR_WARNING}${boost_ver}${COLOR_RESET} < ${COLOR_INFO}${REQ_BOOST}${COLOR_RESET})."
    missing_packages+=("libboost-dev" "libboost-all-dev")
fi

# 4. Check GeographicLib
geo_ver=$(get_geographic_version)
if [ "$geo_ver" != "0" ] && version_ge "$geo_ver" "$REQ_GEOGRAPHIC"; then
    echo -e "${COLOR_SUCCESS}[SUCCESS]${COLOR_RESET} GeographicLib found: version ${COLOR_SUCCESS}${geo_ver}${COLOR_RESET} (>= ${COLOR_INFO}${REQ_GEOGRAPHIC}${COLOR_RESET})"
else
    echo -e "${COLOR_WARNING}[WARNING]${COLOR_RESET} GeographicLib not found or insufficient version (${COLOR_WARNING}${geo_ver}${COLOR_RESET} < ${COLOR_INFO}${REQ_GEOGRAPHIC}${COLOR_RESET})."
    missing_packages+=("libgeographic-dev")
fi

# 5. Check Crypto++
crypto_ver=$(get_cryptopp_version)
if [ "$crypto_ver" != "0" ] && version_ge "$crypto_ver" "$REQ_CRYPTOPP"; then
    echo -e "${COLOR_SUCCESS}[SUCCESS]${COLOR_RESET} Crypto++ found: version ${COLOR_SUCCESS}${crypto_ver}${COLOR_RESET} (>= ${COLOR_INFO}${REQ_CRYPTOPP}${COLOR_RESET})"
else
    echo -e "${COLOR_WARNING}[WARNING]${COLOR_RESET} Crypto++ not found or insufficient version (${COLOR_WARNING}${crypto_ver}${COLOR_RESET} < ${COLOR_INFO}${REQ_CRYPTOPP}${COLOR_RESET})."
    missing_packages+=("libcrypto++-dev")
fi

# 6. Check OpenSSL (Optional backend)
openssl_ver=$(get_openssl_version)
if [ "$openssl_ver" != "0" ]; then
    echo -e "${COLOR_SUCCESS}[SUCCESS]${COLOR_RESET} OpenSSL found: version ${COLOR_SUCCESS}${openssl_ver}${COLOR_RESET}"
else
    echo -e "${COLOR_WARNING}[WARNING]${COLOR_RESET} OpenSSL not found. Marking optional package ${COLOR_INFO}'libssl-dev'${COLOR_RESET} for installation."
    missing_packages+=("libssl-dev" "openssl")
fi

# ------------------------------------------------------------------------------
# Install Missing Dependencies
# ------------------------------------------------------------------------------
if [ ${#missing_packages[@]} -gt 0 ]; then
    echo -e "${COLOR_WARNING}[WARNING] The following required dependencies are missing or outdated:${COLOR_RESET} ${COLOR_INFO}${missing_packages[*]}${COLOR_RESET}"
    echo -e "${COLOR_INFO}[*] Requesting root privileges to install missing packages...${COLOR_RESET}"
    
    # Check if apt-get is available
    if ! command -v apt-get >/dev/null 2>&1; then
        echo -e "${COLOR_DANGER}[ERROR] apt-get package manager not found. Please install the dependencies manually.${COLOR_RESET}" >&2
        exit 1
    fi
    
    sudo apt-get update
    sudo apt-get install -y "${missing_packages[@]}"
    echo -e "${COLOR_SUCCESS}[SUCCESS] Prerequisites successfully installed via package manager.${COLOR_RESET}"
else
    echo -e "${COLOR_SUCCESS}[SUCCESS] All prerequisites are satisfied. Skipping dependency installation.${COLOR_RESET}"
fi

# Get the script directory as the root path
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ------------------------------------------------------------------------------
# Action Helper Functions
# ------------------------------------------------------------------------------

apply_patches() {
    local target_dir="$1"
    echo -e "${COLOR_INFO}[*] Preparing workspace at ${target_dir}...${COLOR_RESET}"
    
    # ==========================================
    # TODO / PLACEHOLDER: Insert patch commands
    # ==========================================
    # Add your custom patch applications here.
    # E.g., patch -p1 < custom_mitigation.patch
    # ==========================================
    echo -e "${COLOR_WARNING}[WARNING] TODO: Insert custom patch application commands in this block.${COLOR_RESET}"
    # ==========================================
    
    echo -e "${COLOR_SUCCESS}[SUCCESS] Patch configuration successfully applied.${COLOR_RESET}"
}

revert_patches() {
    local target_dir="$1"
    echo -e "${COLOR_INFO}[*] Preparing workspace at ${target_dir}...${COLOR_RESET}"
    
    # ==========================================
    # TODO / PLACEHOLDER: Insert unpatch commands
    # ==========================================
    # Add your commands to revert/remove patches.
    # E.g., patch -R -p1 < custom_mitigation.patch
    # ==========================================
    echo -e "${COLOR_WARNING}[WARNING] TODO: Insert custom patch reversion commands in this block.${COLOR_RESET}"
    # ==========================================
    
    echo -e "${COLOR_SUCCESS}[SUCCESS] Patch configuration successfully reverted.${COLOR_RESET}"
}

compile_library() {
    local target_dir="$1"
    local mode_name="$2"
    echo -e "${COLOR_PRIMARY}======================================================================${COLOR_RESET}"
    echo -e "${COLOR_PRIMARY}[*] Compiling Vanetza Library at ${target_dir}...${COLOR_RESET}"
    echo -e "${COLOR_PRIMARY}======================================================================${COLOR_RESET}"

    if [ ! -d "$target_dir" ]; then
        echo -e "${COLOR_DANGER}[ERROR] Target directory does not exist: ${target_dir}${COLOR_RESET}" >&2
        exit 1
    fi

    local build_dir="${target_dir}/build"
    mkdir -p "$build_dir"
    cd "$build_dir"

    echo -e "${COLOR_INFO}[CMAKE] Running CMake configuration...${COLOR_RESET}"
    cmake ..

    local cores=$(nproc)
    echo -e "${COLOR_INFO}[MAKE] Starting compilation on ${COLOR_SUCCESS}${cores}${COLOR_RESET} ${COLOR_INFO}CPU cores...${COLOR_RESET}"
    make -j"${cores}"

    echo -e "${COLOR_SUCCESS}[SUCCESS] Vanetza library compilation complete in ${COLOR_WARNING}${mode_name}${COLOR_RESET} mode."
    echo -e "${COLOR_PRIMARY}======================================================================${COLOR_RESET}"
}

# ------------------------------------------------------------------------------
# Run Requested Actions
# ------------------------------------------------------------------------------

if [ "$MODE" == "patch" ]; then
    echo -e "${COLOR_PRIMARY}======================================================================${COLOR_RESET}"
    echo -e "${COLOR_PRIMARY}[*] Step 2: Processing Patch Configuration...${COLOR_RESET}"
    echo -e "${COLOR_PRIMARY}======================================================================${COLOR_RESET}"
    apply_patches "${SCRIPT_DIR}/vanetza_patched"
    compile_library "${SCRIPT_DIR}/vanetza_patched" "patch"

elif [ "$MODE" == "unpatch" ]; then
    echo -e "${COLOR_PRIMARY}======================================================================${COLOR_RESET}"
    echo -e "${COLOR_PRIMARY}[*] Step 2: Processing Patch Configuration...${COLOR_RESET}"
    echo -e "${COLOR_PRIMARY}======================================================================${COLOR_RESET}"
    revert_patches "${SCRIPT_DIR}/vanetza_unpatched"
    compile_library "${SCRIPT_DIR}/vanetza_unpatched" "unpatch"

elif [ "$MODE" == "all" ]; then
    echo -e "${COLOR_PRIMARY}======================================================================${COLOR_RESET}"
    echo -e "${COLOR_PRIMARY}[*] Step 2: Processing Patch Configuration for 'unpatch'...${COLOR_RESET}"
    echo -e "${COLOR_PRIMARY}======================================================================${COLOR_RESET}"
    revert_patches "${SCRIPT_DIR}/vanetza_unpatched"
    compile_library "${SCRIPT_DIR}/vanetza_unpatched" "unpatch"

    echo -e "${COLOR_PRIMARY}======================================================================${COLOR_RESET}"
    echo -e "${COLOR_PRIMARY}[*] Step 3: Processing Patch Configuration for 'patch'...${COLOR_RESET}"
    echo -e "${COLOR_PRIMARY}======================================================================${COLOR_RESET}"
    apply_patches "${SCRIPT_DIR}/vanetza_patched"
    compile_library "${SCRIPT_DIR}/vanetza_patched" "patch"
fi
