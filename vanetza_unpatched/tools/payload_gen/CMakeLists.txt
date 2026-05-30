add_executable(payload_gen
    main.cpp
)

# 參考你的環境，直接 link 整個 vanetza 即可
target_link_libraries(payload_gen PUBLIC vanetza)