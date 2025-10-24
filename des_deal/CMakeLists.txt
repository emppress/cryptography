add_library(libdes_deal_include INTERFACE)
target_include_directories(libdes_deal_include INTERFACE
        include
)

add_library(libutils
        src/bit_operations.cpp
        src/block_operations.cpp)
target_link_libraries(libutils PUBLIC libdes_deal_include)

add_library(libfeistel src/feistel_network.cpp)
target_link_libraries(libfeistel PUBLIC libdes_deal_include)

add_library(libcrypto_context
        src/context.cpp)
target_link_libraries(libcrypto_context PUBLIC libdes_deal_include)

add_library(libdes src/des.cpp)
target_link_libraries(libdes PUBLIC libfeistel libcrypto_context libutils)

add_library(libdeal src/deal.cpp)
target_link_libraries(libdeal PUBLIC libdes)

add_executable(des_tests
        tests/test_des.cpp
)

target_link_libraries(des_tests
        PRIVATE
        libdes
        GTest::gtest GTest::gtest_main
)

add_executable(deal_tests
        tests/test_deal.cpp
)

target_link_libraries(deal_tests
        PRIVATE
        libdeal
        GTest::gtest GTest::gtest_main
)
