cmake_minimum_required(VERSION 3.27)
project(sbs C)

set(CMAKE_C_STANDARD 11)

add_executable(sbs src/main.c
        src/accounting/user.h
        src/accounting/user.c)

add_subdirectory(libs/mbedtls)
target_link_libraries(sbs
        PUBLIC
        mbedtls)

add_subdirectory(libs/aes_crypt)
target_link_libraries(sbs
        PUBLIC
        aes_crypt)
include_directories("${CMAKE_SOURCE_DIR}/libs/aes_crypt/include")

target_link_libraries(sbs PUBLIC readline)