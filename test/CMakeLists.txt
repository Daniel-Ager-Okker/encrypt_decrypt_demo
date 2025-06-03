cmake_minimum_required(VERSION 3.23 FATAL_ERROR)
project(test-aes-demo CXX)
set(CMAKE_CXX_STANDARD 20)

find_package(GTest REQUIRED)

add_executable(${PROJECT_NAME}
    ./main.cpp
)

target_include_directories(${PROJECT_NAME} PRIVATE
    GTest/include
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    gtest
    gtest_main

    aes-demo
)

include(GoogleTest)
gtest_discover_tests(${PROJECT_NAME})

set(USE_ASAN true)
if (${USE_ASAN})
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror -fsanitize=undefined -fsanitize=address")
    target_link_options(${PROJECT_NAME} BEFORE PUBLIC -fsanitize=undefined PUBLIC -fsanitize=address)
endif()

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})

