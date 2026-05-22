add_executable(qos_measure
    qos_measure.cpp
    pre_filter.cpp
    router_fuzzing_context.cpp
)

target_link_libraries(qos_measure PUBLIC vanetza)