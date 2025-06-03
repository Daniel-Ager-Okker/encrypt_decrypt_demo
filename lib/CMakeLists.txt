cmake_minimum_required(VERSION 3.23 FATAL_ERROR)

project(aes-demo CXX)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_library(${PROJECT_NAME} STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/common.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/decryption.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/encryption.cpp
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    OpenSSL::SSL
)

# Public headers
target_sources(${PROJECT_NAME} PUBLIC
    FILE_SET aes_demo_HEADERS
    TYPE HEADERS
    BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include/
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/include/aes_demo/decryption.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/aes_demo/encryption.h
)