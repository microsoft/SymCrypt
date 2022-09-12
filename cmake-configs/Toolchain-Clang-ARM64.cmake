# This toolchain file configures ARM64 cross-compilation with clang.
# To use the toolchain file, run cmake .. --toolchain="../cmake-configs/Toolchain-Clang-ARM64.cmake"
# Note: the --toolchain argument is only available in CMake v3.21 and newer. Prior to that version, you will have to
# specify -DCMAKE_TOOLCHAIN_FILE instead, which may cause a spurious warning about an unused variable.

set(CMAKE_SYSTEM_PROCESSOR ARM64)
set(TARGET_TRIPLE aarch64-linux-gnu)

# Currently only use clang as it makes cross-compilation easier
set(CMAKE_ASM_COMPILER_TARGET ${TARGET_TRIPLE})
set(CMAKE_C_COMPILER clang)
set(CMAKE_C_COMPILER_TARGET ${TARGET_TRIPLE})
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_CXX_COMPILER_TARGET ${TARGET_TRIPLE})

# Point clang sysroot to cross compilation toolchain when cross compiling
if(NOT CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64")
    # C/C++ toolchain (installed on Ubuntu using apt-get gcc-aarch64-linux-gnu g++-aarch64-linux-gnu)
    set(CMAKE_SYSROOT_COMPILE /usr/${TARGET_TRIPLE})

    # We would expect setting SYSROOT to be sufficient for clang to cross-compile with the gcc-aarch64-linux-gnu
    # toolchain, but it seems that this misses a few key header files for C++...
    # Hacky solution which seems to work for Ubuntu + clang:
    # Get CMake to find the appropriate include directory and explicitly include it
    # Seems like there should be a better way to install cross-compilation tools, or specify search paths to clang
    find_path(CXX_CROSS_INCLUDE_DIR NAMES ${TARGET_TRIPLE} PATHS /usr/${TARGET_TRIPLE}/include/c++/ PATH_SUFFIXES 15 14 13 12 11 10 9 8 7 6 5 NO_DEFAULT_PATH)
    add_compile_options(-I${CXX_CROSS_INCLUDE_DIR}/${TARGET_TRIPLE})
endif()