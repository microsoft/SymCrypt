# This toolchain file configures ARM cross-compilation with GCC.
# To use the toolchain file, run cmake .. --toolchain="../cmake-configs/Toolchain-GCC-ARM.cmake"
# Note: the --toolchain argument is only available in CMake v3.21 and newer. Prior to that version, you will have to
# specify -DCMAKE_TOOLCHAIN_FILE instead, which may cause a spurious warning about an unused variable.

set(CMAKE_SYSTEM_PROCESSOR ARM)
set(TARGET_TRIPLE arm-linux-gnueabihf)

set(CMAKE_ASM_COMPILER_TARGET ${TARGET_TRIPLE})
set(CMAKE_C_COMPILER arm-linux-gnueabihf-gcc)

set(CMAKE_C_COMPILER_TARGET ${TARGET_TRIPLE})
set(CMAKE_CXX_COMPILER arm-linux-gnueabihf-g++)
set(CMAKE_CXX_COMPILER_TARGET ${TARGET_TRIPLE})

if(NOT CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "ARM|arm")
    # C/C++ toolchain (installed on Ubuntu using apt-get gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf)
    set(CMAKE_SYSROOT_COMPILE /usr/${TARGET_TRIPLE})

    find_path(CXX_CROSS_INCLUDE_DIR NAMES ${TARGET_TRIPLE} PATHS /usr/${TARGET_TRIPLE}/include/ /usr/${TARGET_TRIPLE}/include/c++/ PATH_SUFFIXES 15 14 13 12 11 10 9 8 7 6 5 NO_DEFAULT_PATH)
    add_compile_options(-I${CXX_CROSS_INCLUDE_DIR}/${TARGET_TRIPLE})
endif()