add_library(rijndael_include INTERFACE)
target_include_directories(rijndael_include INTERFACE include)

add_library(librijndael
        src/rijndael_transform.cpp
        src/rijndael_key.cpp
        src/rijndael.cpp
)
target_link_libraries(librijndael PUBLIC
        rijndael_include
        interfaces
)

add_executable(rijndael_tests
        tests/test_rijndael.cpp
)
target_link_libraries(rijndael_tests
        PRIVATE
        librijndael
        libcrypto_context
        GTest::gtest
)