# This toolchain file configures CMake options for Windows AMD64 compilation with CPU optimizations.
# To use the toolchain file, run cmake .. -DCMAKE_TOOLCHAIN_FILE=cmake-toolchain/windows-amd64.cmake

# Require Windows 10 SDK version 18362 for BCRYPT_TLS_CBC_HMAC_VERIFY_FLAG
set(CMAKE_SYSTEM_VERSION 10.0.18362)

# Set CMake variables that subsequent CMake scripts can check against
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR AMD64)

# For now this is just used for separating the output directories
set(SYMCRYPT_TARGET_ENV WindowsUserMode)

# Define _AMD64_ to set up the correct SymCrypt macros, e.g. SYMCRYPT_CPU_AMD64
add_compile_options(-D_AMD64_)