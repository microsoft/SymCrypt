# This toolchain file configures CMake options for Linux User Mode X86 compilation with CPU optimizations.
# To use the toolchain file, run cmake .. -DCMAKE_TOOLCHAIN_FILE="cmake-toolchain/LinuxUserMode-X86.cmake"

# Set CMake variables that subsequent CMake scripts can check against
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR X86)

# For now this is just used for separating the output directories
set(SYMCRYPT_TARGET_ENV LinuxUserMode)

add_compile_options("-m32")
add_link_options("-m32")

# 32-bit ASM needs to be translated from MASM to SymCryptAsm, so we don't support ASM optimizations
# on 32-bit Linux for now
add_compile_options("-DSYMCRYPT_IGNORE_PLATFORM")

set(CMAKE_ASM_FLAGS "-x assembler-with-cpp")