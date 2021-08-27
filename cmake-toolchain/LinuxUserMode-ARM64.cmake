# This toolchain file configures CMake options for Linux User Mode ARM64 compilation with CPU optimizations.
# To use the toolchain file, run cmake .. -DCMAKE_TOOLCHAIN_FILE=cmake-toolchain/LinuxUserMode-ARM64.cmake

# Set CMake variables that subsequent CMake scripts can check against
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR ARM64)

set(TARGET_TRIPLE aarch64-linux-gnu)

# Currently only use clang as it makes cross-compilation easier
set(CMAKE_C_COMPILER clang)
set(CMAKE_C_COMPILER_TARGET ${TARGET_TRIPLE})
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_CXX_COMPILER_TARGET ${TARGET_TRIPLE})

# For now this is just used for separating the output directories
set(SYMCRYPT_TARGET_ENV LinuxUserMode)

# Define _ARM64_ to set up the correct SymCrypt macros, e.g. SYMCRYPT_CPU_ARM64
add_compile_options(-D_ARM64_)
add_compile_options(-O3)

# Enable FIPS build
add_compile_options(-DSYMCRYPT_DO_FIPS_SELFTESTS=1)

# Enable a baseline of features for the compiler to support everywhere
# Assumes that the compiler will not emit crypto instructions as a result of normal C code
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=armv8a+simd+crypto")

# set(CMAKE_ASM_FLAGS "-x assembler-with-cpp")
