add_library(libcrypto_context
        src/context.cpp)
target_link_libraries(libcrypto_context PUBLIC libutils interfaces)
target_include_directories(libcrypto_context PUBLIC include)