cmake_minimum_required(VERSION 3.13.0)

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
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/module/${CMAKE_SYSTEM_PROCESSOR}/${SYMCRYPT_TARGET_ENV})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/exe/${CMAKE_SYSTEM_PROCESSOR}/${SYMCRYPT_TARGET_ENV})

if(WIN32 AND SYMCRYPT_TARGET_ENV MATCHES "WindowsUserMode")
    # Enable ASM_MASM. Annoyingly, this has to be done in the main CMake file rather than in the
    # toolchain file
    enable_language(ASM_MASM)
    add_compile_options(/MP)
    add_compile_options(/Zp8)
    # Remove /RTC1, incompatible of /Ox
    string( REPLACE "/RTC1" "" CMAKE_CXX_FLAGS_DEBUG ${CMAKE_CXX_FLAGS_DEBUG})
    string( REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG ${CMAKE_C_FLAGS_DEBUG})
    string( REPLACE "/RTC1" "" CMAKE_CXX_FLAGS_RELEASE ${CMAKE_CXX_FLAGS_RELEASE})
    string( REPLACE "/RTC1" "" CMAKE_C_FLAGS_RELEASE ${CMAKE_C_FLAGS_RELEASE})
    # /Od incompatible with /Ox
    string( REPLACE "/Od" "" CMAKE_CXX_FLAGS_DEBUG ${CMAKE_CXX_FLAGS_DEBUG})
    string( REPLACE "/Od" "" CMAKE_C_FLAGS_DEBUG ${CMAKE_C_FLAGS_DEBUG})
    string( REPLACE "/Od" "" CMAKE_CXX_FLAGS_RELEASE ${CMAKE_CXX_FLAGS_RELEASE})
    string( REPLACE "/Od" "" CMAKE_C_FLAGS_RELEASE ${CMAKE_C_FLAGS_RELEASE})

    if(CMAKE_BUILD_TYPE MATCHES Release)
        add_compile_options(/Oxs)
        add_compile_options(/GL)
        add_compile_options(/GF)
        add_compile_options(/Gy)
        add_compile_options(/Gw)
    endif()
elseif(NOT WIN32)
    enable_language(ASM)
    add_compile_options(-Wno-deprecated-declarations -Wno-deprecated)
    add_compile_options(-g)
    add_compile_options(-Wno-multichar)
    add_compile_options(-fPIC)
    add_compile_options(-fno-stack-protector)
    add_compile_options(-fno-plt)
    add_compile_options(-fno-builtin-bcmp)

    # In Sanitize version, enable sanitizers
    if (CMAKE_BUILD_TYPE MATCHES Sanitize)
        add_compile_options(-fsanitize=address)
        add_compile_options(-fsanitize=leak)

        # add_compile_options(-fsanitize=undefined)
        # Not using undefined as we do not want to include alignment sanitizer
        add_compile_options(-fsanitize=bool)
        add_compile_options(-fsanitize=builtin)
        add_compile_options(-fsanitize=bounds)
        add_compile_options(-fsanitize=enum)
        add_compile_options(-fsanitize=float-cast-overflow)
        add_compile_options(-fsanitize=float-divide-by-zero)
        add_compile_options(-fsanitize=integer-divide-by-zero)
        add_compile_options(-fsanitize=nonnull-attribute)
        add_compile_options(-fsanitize=pointer-overflow)
        add_compile_options(-fsanitize=return)
        add_compile_options(-fsanitize=returns-nonnull-attribute)
        add_compile_options(-fsanitize=shift)
        add_compile_options(-fsanitize=signed-integer-overflow)
        add_compile_options(-fsanitize=unreachable)
        add_compile_options(-fsanitize=vla-bound)
        add_compile_options(-fsanitize=vptr)
        add_compile_options(-fno-sanitize-recover=all)
        add_link_options(-fsanitize=address)
        add_link_options(-fsanitize=leak)
        add_link_options(-fsanitize=bool)
        add_link_options(-fsanitize=builtin)
        add_link_options(-fsanitize=bounds)
        add_link_options(-fsanitize=enum)
        add_link_options(-fsanitize=float-cast-overflow)
        add_link_options(-fsanitize=float-divide-by-zero)
        add_link_options(-fsanitize=integer-divide-by-zero)
        add_link_options(-fsanitize=nonnull-attribute)
        add_link_options(-fsanitize=pointer-overflow)
        add_link_options(-fsanitize=return)
        add_link_options(-fsanitize=returns-nonnull-attribute)
        add_link_options(-fsanitize=shift)
        add_link_options(-fsanitize=signed-integer-overflow)
        add_link_options(-fsanitize=unreachable)
        add_link_options(-fsanitize=vla-bound)
        add_link_options(-fsanitize=vptr)
        add_link_options(-fno-sanitize-recover=all)
    endif()

    # GCC and clang unroll more aggressively than they should for best performance
    # When we want to unroll loops, we unroll in the source code, so tell the compiler not to unroll
    # (clang seems to respect this option globally, but I could only make GCC behave in AES-GCM by
    # using GCC-specific pragmas for the loops of interest)
    add_compile_options(-fno-unroll-loops)
endif()

if(CMAKE_BUILD_TYPE MATCHES Release)
    message("Release mode")
else()
    message("Debug mode")
    add_compile_options(-DDBG=1)
endif()

include_directories(inc)
include_directories(${CMAKE_BINARY_DIR}/inc)
include(build/buildInfo.cmake)

add_subdirectory(lib)

if(NOT WIN32 AND NOT CMAKE_BUILD_TYPE MATCHES Sanitize)
    # Module integrity check is seen as OOB access by sanitizers, and sanitizer instrumentation
    # breaks integrity check assumptions. Only enable module when not running with sanitizers
    add_subdirectory(module)
endif()

add_subdirectory(unittest)