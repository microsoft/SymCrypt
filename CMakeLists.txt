cmake_minimum_required(VERSION 2.8.9)

add_compile_options(-DSYMCRYPT_IGNORE_PLATFORM)

if(WIN32)
    # Require Windows 10 SDK version 18362 for BCRYPT_TLS_CBC_HMAC_VERIFY_FLAG
    set(CMAKE_SYSTEM_VERSION 10.0.18362)
else()
    add_compile_options(-Wno-deprecated-declarations -Wno-deprecated)
    add_compile_options(-g)
    add_compile_options(-Wno-multichar)
endif()

project(SymCrypt)

include_directories(inc)
include_directories(${CMAKE_BINARY_DIR}/inc)
include(build/buildInfo.cmake)

add_subdirectory(lib)
add_subdirectory(unittest)