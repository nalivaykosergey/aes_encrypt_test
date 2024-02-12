cmake_minimum_required(VERSION 3.27)
project(aes_crypt C)

set(CMAKE_C_STANDARD 11)

set(src_files include/aes_crypt.h
        src/aes_crypt.c
        src/aes_math.c
        src/aes_crypt_transformations.c
        src/aes_constant_values.c)
set(headers include/aes_crypt.h)

add_library(aes_crypt SHARED ${src_files} ${headers})

set_target_properties(aes_crypt PROPERTIES
        PUBLIC_HEADER "${headers}"
)
target_include_directories(aes_crypt PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:include>
)


