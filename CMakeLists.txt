cmake_minimum_required(VERSION 2.8.9)

project(SymCrypt)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

# SYMCRYPT_TARGET_ENV should be set by the toolchain file. If no toolchain file is specified, we will build
# with no CPU-specific optimizations. Some toolchain files may require additional arguments; see the files
# under cmake-toolchain for more information.
if(NOT SYMCRYPT_TARGET_ENV)
    message(STATUS "No toolchain file specified (or toolchain file did not set SYMCRYPT_TARGET_ENV).")
    message(STATUS "Building for generic environment with SYMCRYPT_IGNORE_PLATFORM.")
    set(SYMCRYPT_TARGET_ENV Generic)
    add_compile_options(-DSYMCRYPT_IGNORE_PLATFORM)
else()
    # Just to avoid an unused variable warning
    message(STATUS "Using toolchain file: ${CMAKE_TOOLCHAIN_FILE}.")
endif()

message(STATUS "Host: ${CMAKE_HOST_SYSTEM_NAME} ${CMAKE_HOST_SYSTEM_PROCESSOR}")
message(STATUS "Target: ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_PROCESSOR} ${SYMCRYPT_TARGET_ENV}")

# Set output directories binaries
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/${CMAKE_SYSTEM_PROCESSOR}/${SYMCRYPT_TARGET_ENV})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/${CMAKE_SYSTEM_PROCESSOR}/${SYMCRYPT_TARGET_ENV})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/exe/${CMAKE_SYSTEM_PROCESSOR}/${SYMCRYPT_TARGET_ENV})

if(WIN32 AND SYMCRYPT_TARGET_ENV MATCHES "WindowsUserMode")
    # Set DBG=1 and enable ASM_MASM. Annoyingly, this has to be done in the main CMake file rather than in
    # the toolchain file
    add_compile_options(-DDBG=1)
    enable_language(ASM_MASM)
    add_compile_options(/MP)
elseif(NOT WIN32)
    add_compile_options(-Wno-deprecated-declarations -Wno-deprecated)
    add_compile_options(-g)
    add_compile_options(-Wno-multichar)
endif()

include_directories(inc)
include_directories(${CMAKE_BINARY_DIR}/inc)
include(build/buildInfo.cmake)

add_subdirectory(lib)
add_subdirectory(unittest)