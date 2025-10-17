find_package(Boost REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(GMP REQUIRED gmp)

add_library(libcrypto_math INTERFACE)
target_include_directories(libcrypto_math INTERFACE
        include
)
target_link_libraries(libcrypto_math INTERFACE
        Boost::boost
        gmp
)

add_library(librsa src/rsa.cpp)
target_link_libraries(librsa PUBLIC libcrypto_math)

add_executable(rsa_tests
        tests/test_rsa.cpp
)

target_link_libraries(rsa_tests
        PRIVATE
        librsa
        GTest::gtest GTest::gtest_main
)

enable_testing()
add_test(NAME RSATests COMMAND rsa_tests)