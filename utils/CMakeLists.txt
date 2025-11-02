add_library(libutils
        src/bit_operations.cpp
        src/block_operations.cpp
)
target_include_directories(libutils PUBLIC include)