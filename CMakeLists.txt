cmake_minimum_required(VERSION 3.14)
project(metaling)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

# Avoid warning about DOWNLOAD_EXTRACT_TIMESTAMP in CMake 3.24:
cmake_policy(SET CMP0135 NEW)

add_executable(metaling)

find_library(METAL_LIB Metal)
find_library(FOUNDATION_LIB Foundation)

# ------ Downloading and including metal c++ bindings. ------ 

# Throw an error if xcrun not found.
execute_process(COMMAND zsh "-c" "/usr/bin/xcrun -sdk macosx --show-sdk-version"
                OUTPUT_VARIABLE MACOS_VERSION
                COMMAND_ERROR_IS_FATAL ANY)

message(STATUS "Building with SDK for macOS version ${MACOS_VERSION}")

set(METAL_CPP_URL https://developer.apple.com/metal/cpp/files/metal-cpp_macOS15_iOS18-beta.zip)
if (${MACOS_VERSION} GREATER_EQUAL 15.0)
    set(METAL_VERSION METAL_3_2)
elseif (${MACOS_VERSION} GREATER_EQUAL 14.2)
    set(METAL_VERSION METAL_3_1)
elseif (${MACOS_VERSION} GREATER_EQUAL 14.0)
    set(METAL_VERSION METAL_3_0)
else()
    message(FATAL_ERROR "metaling requires macOS SDK >= 14.0 to be built")
endif()

FetchContent_Declare(
    metal_cpp
    URL ${METAL_CPP_URL}
)

FetchContent_MakeAvailable(metal_cpp)
target_include_directories(
    metaling PUBLIC
    $<BUILD_INTERFACE:${metal_cpp_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/metal_cpp>
)

target_link_libraries(
    metaling PUBLIC
    ${METAL_LIB}
    ${FOUNDATION_LIB}
)

add_compile_definitions(${MLX_METAL_VERSION})

# -----------------------------------------------------------

# Define macro with the root directory
target_compile_definitions(metaling PRIVATE ROOT_DIR="${CMAKE_SOURCE_DIR}")

# Add frequently included header files for pre-compiling.
# target_precompile_headers is supported by CMake 3.16.0 or newer.
if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.16.0")
    # ccache needs this flag along with `sloppiness = pch_defines,time_macros`
    # to enable caching
    target_compile_options(metaling PRIVATE -fpch-preprocess)
endif()

# Try to use mold linker.
find_program(MOLD_EXISTS "mold")
if(MOLD_EXISTS)
    target_link_options(metaling PRIVATE -fuse-ld=mold)
endif()

# Turn on -flto.
# set_property(TARGET metaling PROPERTY INTERPROCEDURAL_OPTIMIZATION ON)

# Turn on address sanitzer.
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(metaling PRIVATE -fsanitize=address -fsanitize=undefined)
    target_link_options(metaling PRIVATE -fsanitize=address -fsanitize=undefined)
endif()

target_compile_options(metaling PRIVATE
  -fno-exceptions
  -fno-unwind-tables
  -fno-asynchronous-unwind-tables
  -Wall
  -Wextra
  -Wno-sign-compare
  -Wno-unused-function
  -Wno-unused-parameter
  -Wno-missing-field-initializers
  -ggnu-pubnames
)

target_sources(metaling PRIVATE
    src/main.cc
    src/metal.cc
    src/common.cc
)
