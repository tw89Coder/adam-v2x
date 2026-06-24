add_executable(qos-harness
    src/main.cpp
    src/file_manager.cpp
    src/metrics_collector.cpp
    src/traffic_generator.cpp
    src/harness_engine.cpp
    src/console_presenter.cpp
    src/amplification_profiler.cpp
    src/pre_filter.cpp
    src/router_fuzzing_context.cpp
)

target_include_directories(qos-harness PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(qos-harness PUBLIC vanetza)

get_filename_component(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)

target_compile_definitions(qos-harness PRIVATE REPO_ROOT="${REPO_ROOT}")