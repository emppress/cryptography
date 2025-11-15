add_library(libidea src/idea.cpp)
target_include_directories(libidea PUBLIC include)
target_link_libraries(libidea
        PUBLIC
        interfaces
        libcrypto_context
)

add_executable(main src/main.cpp)
target_link_libraries(main PUBLIC libidea)

add_executable(idea_tests
        tests/test_idea.cpp
)
target_link_libraries(idea_tests
        PRIVATE
        libidea
        GTest::gtest GTest::gtest_main
)