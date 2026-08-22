#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="${ROOT_DIR}/vanetza_unpatched"
BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/vanetza_unpatched/build-unit-tests}"

cmake -S "${SOURCE_DIR}" -B "${BUILD_DIR}" \
    -DBUILD_TESTS=OFF \
    -DBUILD_QOS_HARNESS_TESTS=ON
cmake --build "${BUILD_DIR}" --target qos-harness-unit-tests --parallel
"${BUILD_DIR}/bin/qos-harness-unit-tests"
