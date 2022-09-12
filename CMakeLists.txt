cmake_minimum_required(VERSION 3.13.0)

if(WIN32)
    # Require Windows 10 SDK version 18362 for BCRYPT_TLS_CBC_HMAC_VERIFY_FLAG
    # Must be done before the "project" directive
    set(CMAKE_SYSTEM_VERSION 10.0.18362)
endif()

# Parse the version number from symcrypt_internal_shared.inc
file(READ "${CMAKE_SOURCE_DIR}/inc/symcrypt_internal_shared.inc" SYMCRYPT_VERSION_FILE_CONTENTS)

string(REGEX MATCH "SYMCRYPT_CODE_VERSION_API[ \t]+([0-9]+)" _ ${SYMCRYPT_VERSION_FILE_CONTENTS})
set(SYMCRYPT_CODE_VERSION_API ${CMAKE_MATCH_1})

string(REGEX MATCH "SYMCRYPT_CODE_VERSION_MINOR[ \t]+([0-9]+)" _ ${SYMCRYPT_VERSION_FILE_CONTENTS})
set(SYMCRYPT_CODE_VERSION_MINOR ${CMAKE_MATCH_1})

string(REGEX MATCH "SYMCRYPT_CODE_VERSION_PATCH[ \t]+([0-9]+)" _ ${SYMCRYPT_VERSION_FILE_CONTENTS})
set(SYMCRYPT_CODE_VERSION_PATCH ${CMAKE_MATCH_1})

message(STATUS "SymCrypt version ${SYMCRYPT_CODE_VERSION_API}.${SYMCRYPT_CODE_VERSION_MINOR}.${SYMCRYPT_CODE_VERSION_PATCH}")

project(SymCrypt
    VERSION ${SYMCRYPT_CODE_VERSION_API}.${SYMCRYPT_CODE_VERSION_MINOR}.${SYMCRYPT_CODE_VERSION_PATCH}
    DESCRIPTION "Cryptographic library"
    HOMEPAGE_URL "https://github.com/microsoft/SymCrypt")

option(
    SYMCRYPT_USE_ASM
    "When enabled, SymCrypt will use ASM implementations of performance-critical functions where available.
    Not supported on all platforms/architectures."
    ON)

if(NOT SYMCRYPT_USE_ASM)
    add_compile_options("-DSYMCRYPT_IGNORE_PLATFORM")
endif()

option(
    SYMCRYPT_FIPS_BUILD
    "When enabled, SymCrypt will build FIPS-compliant modules with self-tests enabled. Not supported on all platforms/architectures.
    On Windows, this option is ignored, as self-tests are performed at a higher layer."
    ON)

if(SYMCRYPT_FIPS_BUILD)
    add_compile_options(-DSYMCRYPT_DO_FIPS_SELFTESTS=1)
endif()

include(${CMAKE_SOURCE_DIR}/cmake-configs/SymCrypt-Platforms.cmake)

if(NOT DEFINED CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

message(STATUS "Host: ${CMAKE_HOST_SYSTEM_NAME} ${CMAKE_HOST_SYSTEM_PROCESSOR}")
message(STATUS "Target: ${CMAKE_SYSTEM_NAME} ${SYMCRYPT_TARGET_ARCH} ${SYMCRYPT_TARGET_ENV}")
message(STATUS "ASM optimizations: ${SYMCRYPT_USE_ASM}")
message(STATUS "FIPS build: ${SYMCRYPT_FIPS_BUILD}")

# Set output directories binaries
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/module)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/exe)

if(CMAKE_BUILD_TYPE MATCHES Release)
    message(STATUS "Release mode")
else()
    message(STATUS "Debug mode")
    add_compile_options(-DDBG=1)
endif()

include_directories(inc)
include_directories(${CMAKE_BINARY_DIR}/inc)
include(build/buildInfo.cmake)

# Process pkg-config file
configure_file(build/symcrypt.pc.in symcrypt.pc @ONLY)

add_subdirectory(lib)

if(NOT WIN32 AND NOT CMAKE_BUILD_TYPE MATCHES Sanitize)
    # Module integrity check is seen as OOB access by sanitizers, and sanitizer instrumentation
    # breaks integrity check assumptions. Only enable module when not running with sanitizers
    add_subdirectory(modules_linux)
endif()

add_subdirectory(unittest)