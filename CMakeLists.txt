cmake_minimum_required(VERSION 3.20)
project(sentinel LANGUAGES CXX)

# The whole point of this build is that a stranger can clone and build it with
# nothing but a C++20 compiler and CMake. No package manager, no network fetch at
# configure time, no FetchContent. Every dependency below is either the standard
# library or a platform socket library that ships with the OS.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

add_library(sentinel_core
    src/siphash.cpp
)
target_include_directories(sentinel_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(MSVC)
    target_compile_options(sentinel_core PRIVATE /W4)
else()
    target_compile_options(sentinel_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

enable_testing()
add_executable(sentinel_tests
    tests/test_main.cpp
    tests/test_bytes.cpp
)
target_link_libraries(sentinel_tests PRIVATE sentinel_core)
target_include_directories(sentinel_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
if(NOT MSVC)
    target_compile_options(sentinel_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Every test case becomes its own CTest entry. The list is produced by the test
# binary itself after it is linked, so the names cannot drift away from the code.
# A placeholder is written at configure time because CTest reads the file before
# anything has been built.
set(SENTINEL_CASES ${CMAKE_CURRENT_BINARY_DIR}/sentinel_test_cases.cmake)
file(WRITE ${SENTINEL_CASES} "# regenerated after each build of sentinel_tests\n")
add_custom_command(TARGET sentinel_tests POST_BUILD
    COMMAND $<TARGET_FILE:sentinel_tests> --ctest-list ${SENTINEL_CASES} $<TARGET_FILE:sentinel_tests>
    BYPRODUCTS ${SENTINEL_CASES}
    VERBATIM
    COMMENT "Registering test cases with CTest"
)
set_property(DIRECTORY APPEND PROPERTY TEST_INCLUDE_FILES ${SENTINEL_CASES})
