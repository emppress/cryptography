cmake_minimum_required(VERSION 3.30)
project(cryptography CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(GTest REQUIRED)
enable_testing()
add_subdirectory(des_deal)
add_subdirectory(rsa)
add_subdirectory(rijndael)
add_subdirectory(crypto_context)
add_subdirectory(utils)
add_subdirectory(rc4)
add_subdirectory(idea)
add_subdirectory(dh)

add_library(interfaces INTERFACE)
target_include_directories(interfaces INTERFACE ./interfaces)


