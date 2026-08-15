add_executable(qos-harness
    src/main.cpp
    src/file_manager.cpp
    src/metrics_collector.cpp
    src/traffic_generator.cpp
    src/harness_engine.cpp
    src/console_presenter.cpp
    src/amplification_profiler.cpp
    src/pre_filter.cpp
    src/runtime_config.cpp
    src/rl_bridge.cpp
    src/router_fuzzing_context.cpp
    src/dataset_builder.cpp
    src/queue_simulator.cpp
    src/socket_engine.cpp
)

target_include_directories(qos-harness PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

find_package(Threads REQUIRED)
target_link_libraries(qos-harness PUBLIC vanetza Threads::Threads atomic)

get_filename_component(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)

target_compile_definitions(qos-harness PRIVATE REPO_ROOT="${REPO_ROOT}")

# Dynamic Architecture Auto-Detection & Optimization (x86_64 vs RPi 4B ARM32 / ARM64)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    # Raspberry Pi 4B (64-bit OS)
    message(STATUS "[QoS-Harness] Auto-detected ARM64 (Raspberry Pi 4B Cortex-A72). Enabling NEON SIMD flags.")
    target_compile_options(qos-harness PRIVATE -O3 -mcpu=cortex-a72 -ffast-math -funroll-loops -fomit-frame-pointer -ftree-vectorize)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm|armv7l|armv8l")
    # Raspberry Pi 4B (32-bit OS)
    message(STATUS "[QoS-Harness] Auto-detected ARM32 (Raspberry Pi 4B Cortex-A72). Enabling NEON SIMD flags.")
    target_compile_options(qos-harness PRIVATE -O3 -mcpu=cortex-a72 -mfpu=neon-fp-armv8 -mfloat-abi=hard -ffast-math -funroll-loops -fomit-frame-pointer -ftree-vectorize)
else()
    # x86_64 / PC / WSL
    message(STATUS "[QoS-Harness] Auto-detected x86_64 host architecture.")
    target_compile_options(qos-harness PRIVATE -O3 -march=native -ffast-math -funroll-loops -ftree-vectorize)
endif()

# Dynamic ONNX Runtime detection and linking
set(ONNXRT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../third_party/onnxruntime")

if(EXISTS "${ONNXRT_ROOT}/include/onnxruntime_cxx_api.h")
    message(STATUS "[QoS-Harness] Found ONNX Runtime at ${ONNXRT_ROOT}. Enabling in-process inference.")
    target_compile_definitions(qos-harness PRIVATE USE_ONNX)
    target_include_directories(qos-harness PRIVATE ${ONNXRT_ROOT}/include)
    target_link_directories(qos-harness PRIVATE ${ONNXRT_ROOT}/lib)
    target_link_libraries(qos-harness PRIVATE onnxruntime)
    
    # Configure RPATH so the dynamic linker can locate libonnxruntime.so at runtime
    set_target_properties(qos-harness PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "${ONNXRT_ROOT}/lib"
    )
endif()

# Add qos-harness-test executable for fast GUI box alignment testing
add_executable(qos-harness-test
    tests/test_presenter.cpp
    src/console_presenter.cpp
)

target_include_directories(qos-harness-test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
