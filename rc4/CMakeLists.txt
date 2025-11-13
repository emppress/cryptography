add_library(rc4 src/rc4.cpp)
target_include_directories(rc4 PUBLIC include)

add_executable(rc4_tests tests/test_rc4.cpp)
target_link_libraries(rc4_tests
        PRIVATE
        rc4
        GTest::gtest GTest::gtest_main
)