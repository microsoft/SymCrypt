cmake_minimum_required(VERSION 3.13.0)

if(WIN32)
    # Require Windows 10 SDK version 18362 for BCRYPT_TLS_CBC_HMAC_VERIFY_FLAG
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
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID}")

# Set output directories binaries
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib/${CMAKE_SYSTEM_PROCESSOR}/${SYMCRYPT_TARGET_ENV})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/module/${CMAKE_SYSTEM_PROCESSOR}/${SYMCRYPT_TARGET_ENV})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/exe/${CMAKE_SYSTEM_PROCESSOR}/${SYMCRYPT_TARGET_ENV})

enable_language(C)
enable_language(CXX)

function(find_windows_sdk)

    # Find the Windows Kits directory.
    get_filename_component(windows_kits_dir
            "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Kits\\Installed Roots;KitsRoot10]" ABSOLUTE)
    set(programfilesx86 "ProgramFiles(x86)")
    if (";${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION};$ENV{UCRTVersion};$ENV{WindowsSDKVersion};" MATCHES [=[;(10\.[0-9.]+)[;\]]]=])
        set(__ucrt_version "${CMAKE_MATCH_1}/")
    else ()
        set(__ucrt_version "*/")
    endif ()

    if (NOT DEFINED CMAKE_MSVC_ARCH)
        if (${CMAKE_SYSTEM_PROCESSOR} MATCHES "^ARM")
            set(CMAKE_MSVC_ARCH "arm")
        elseif (${CMAKE_SYSTEM_PROCESSOR} MATCHES "64$")
            set(CMAKE_MSVC_ARCH "x64")
        else ()
            set(CMAKE_MSVC_ARCH "x86")
        endif ()
    endif ()


    set(WINDOWS_KITS_DIR "" PARENT_SCOPE)
    find_path(WINDOWS_KITS_DIR
            NAMES
            "Redist/${__ucrt_version}ucrt/DLLs/${CMAKE_MSVC_ARCH}/ucrtbase.dll"
            "Redist/ucrt/DLLs/${CMAKE_MSVC_ARCH}/ucrtbase.dll"
            PATHS
            $ENV{CMAKE_WINDOWS_KITS_10_DIR}
            "${windows_kits_dir}"
            "$ENV{ProgramFiles}/Windows Kits/10"
            "$ENV{${programfilesx86}}/Windows Kits/10"
    )
    mark_as_advanced(WINDOWS_KITS_DIR)

    set(WINDOWSSDK_VERSIONS "" PARENT_SCOPE)

    file(GLOB WINDOWSSDK_VERSIONS
            LIST_DIRECTORIES true
            RELATIVE "${WINDOWS_KITS_DIR}/Include"
            "${WINDOWS_KITS_DIR}/Include/*"
    )
    mark_as_advanced(WINDOWSSDK_VERSIONS)

    set(WINDOWSSDK_VERSION "" PARENT_SCOPE)
    set(_WINDOWSSDK_VERSIONS "${WINDOWSSDK_VERSIONS}")
    list(GET _WINDOWSSDK_VERSIONS 0 WINDOWSSDK_VERSION)
    list(REMOVE_AT _WINDOWSSDK_VERSIONS 0)
    foreach(__version "${_WINDOWSSDK_VERSIONS}")
        if ("${__version}" VERSION_GREATER "${WINDOWSSDK_VERSION}")
            set(WINDOWSSDK_VERSION "${__version}")
        endif ()
    endforeach()
    mark_as_advanced(WINDOWSSDK_VERSION)

    set(WINDOWSSDK_INCLUDE_ROOT "${WINDOWS_KITS_DIR}/Include/${WINDOWSSDK_VERSION}" PARENT_SCOPE)
    mark_as_advanced(WINDOWSSDK_INCLUDE_ROOT)

    set(WINDOWSSDK_INCLUDE_DIRS "${WINDOWSSDK_INCLUDE_ROOT}/shared;${WINDOWSSDK_INCLUDE_ROOT}/um" PARENT_SCOPE)
    mark_as_advanced(WINDOWSSDK_INCLUDE_DIRS)

endfunction()


if(MSVC)
    find_windows_sdk()

    if(NOT SYMCRYPT_TARGET_ENV MATCHES "Generic")
        # Enable ASM_MASM. Annoyingly, this has to be done in the main CMake file rather than in the
        # toolchain file
        enable_language(ASM_MASM)
    endif()
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
else()
    if(WIN32)
        find_windows_sdk()
        include_directories(SYSTEM "${WINDOWSSDK_INCLUDE_ROOT}")
        add_compile_definitions(_WIN32_WINNT=0x0A00)
    endif()

    if(NOT SYMCRYPT_TARGET_ENV MATCHES "Generic")
        enable_language(ASM)
        # Suppress noisy warnings about compile options which are ignored for ASM
        # Less messy than restricting most of the below options to only C/CXX!
        add_compile_options($<$<COMPILE_LANGUAGE:ASM>:-Wno-unused-command-line-argument>)
    endif()
    # add_compile_options(-Wall)
    # add_compile_options(-Wno-unknown-pragmas)
    add_compile_options(-Wno-deprecated-declarations -Wno-deprecated)
    add_compile_options(-g)
    add_compile_options(-Wno-multichar)
    add_compile_options(-fPIC)
    add_compile_options(-fno-plt)
    add_compile_options(-fno-builtin-bcmp)

    # Required for cross-compiling from AMD64 to ARM64
    # Avoids error: cast from pointer to smaller type 'uintptr_t' when including <memory> from aarch64-linux-gnu
    add_compile_options(-fms-extensions)

    # GCC and clang unroll more aggressively than they should for best performance
    # When we want to unroll loops, we unroll in the source code, so tell the compiler not to unroll
    # (clang seems to respect this option globally, but I could only make GCC behave in AES-GCM by
    # using GCC-specific pragmas for the loops of interest)
    add_compile_options(-fno-unroll-loops)

    # Do not optimize Debug builds
    if (CMAKE_BUILD_TYPE MATCHES Debug)
        add_compile_options(-O0)
    else()
        add_compile_options(-O3)
    endif()

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
endif()

option(RELEASE_USES_IPO "Enable IPO/LTO/LTCG for Release builds." ON)

if(CMAKE_BUILD_TYPE MATCHES Release)
    message("Release mode")

    include(CheckIPOSupported)
    check_ipo_supported(RESULT HAVE_IPO_SUPPORT OUTPUT IPO_SUPPORT_ERROR)

    if (HAVE_IPO_SUPPORT)
        if (RELEASE_USES_IPO)
            message(STATUS "IPO/LTO/LTCG: supported, enabled")
            set_property(GLOBAL PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
        else ()
            message(STATUS "IPO/LTO/LTCG: supported, disabled")
        endif ()
    else ()
        message(STATUS "IPO/LTO/LTCG: not supported, <${IPO_SUPPORT_ERROR}>")
    endif ()
else()
    message("Debug mode")
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