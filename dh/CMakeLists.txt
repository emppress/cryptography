find_package(Boost REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(GMP REQUIRED gmp)

add_library(libdh src/dh.cpp)
target_include_directories(libdh PUBLIC include PUBLIC ${CMAKE_SOURCE_DIR}/rsa/include)
target_link_libraries(libdh PUBLIC
        Boost::boost
        gmp
)

add_executable(DH_tests tests/test_dh.cpp)
target_link_libraries(DH_tests PRIVATE
        libdh
        GTest::gtest
)