# This toolchain file configures CMake options for Linux User Mode AMD64 compilation with CPU optimizations.
# To use the toolchain file, run cmake .. -DCMAKE_TOOLCHAIN_FILE="cmake-toolchain/LinuxUserMode-AMD64.cmake"

# Set CMake variables that subsequent CMake scripts can check against
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR AMD64)

# For now this is just used for separating the output directories
set(SYMCRYPT_TARGET_ENV LinuxUserMode)

# Define _AMD64_ to set up the correct SymCrypt macros, e.g. SYMCRYPT_CPU_AMD64
add_compile_options(-D_AMD64_)

# Enable FIPS build
add_compile_options(-DSYMCRYPT_DO_FIPS_SELFTESTS=1)

# Enable a baseline of features for the compiler to support everywhere
# Other than for SSSE3 we do not expect the compiler to generate these instructions anywhere other than with intrinsics
#
# We cannot globally enable AVX and later, as we need to keep use of these instructions behind CPU detection, and the
# instructions are definitely useful enough for a smart compiler to use them in C code (i.e. in memcpy)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mssse3 -mxsave -maes -mpclmul -msha -mrdrnd -mrdseed")

set(CMAKE_ASM_FLAGS "-x assembler-with-cpp")