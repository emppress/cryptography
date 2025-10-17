cmake_minimum_required(VERSION 3.30)
project(cryptography CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(GTest REQUIRED)
enable_testing()

add_subdirectory(rsa)



