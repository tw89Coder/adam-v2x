add_executable(qos-harness
    src/main.cpp
    src/file_manager.cpp
    src/metrics_collector.cpp
    src/traffic_generator.cpp
    src/harness_engine.cpp
    src/console_presenter.cpp
    src/amplification_profiler.cpp
    src/pre_filter.cpp
    src/rl_bridge.cpp
    src/router_fuzzing_context.cpp
    src/dataset_builder.cpp
    src/queue_simulator.cpp
)

target_include_directories(qos-harness PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(qos-harness PUBLIC vanetza)

get_filename_component(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)

target_compile_definitions(qos-harness PRIVATE REPO_ROOT="${REPO_ROOT}")

# Dynamic ONNX Runtime detection and linking
set(ONNXRT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../third_party/onnxruntime")

if(EXISTS "${ONNXRT_ROOT}")
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