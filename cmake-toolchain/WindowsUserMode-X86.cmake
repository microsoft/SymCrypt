# This toolchain file configures CMake options for Windows User Mode x86 compilation with CPU optimizations.
# To use the toolchain file, run cmake .. -DCMAKE_TOOLCHAIN_FILE=cmake-toolchain/WindowsUserMode-X86.cmake -A Win32
#
# (The "-A Win32" option seems to be required when compiling on a 64-bit host. Ideally this toolchain file
# should set all the required options, but I haven't figured out how to force 32-bit compilation from the
# toolchain file, so if you don't provide "-A Win32" it will try to use the 64-bit compiler and assembler
# and will fail.)

# Set CMake variables that subsequent CMake scripts can check against
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR X86)

# For now this is just used for separating the output directories
set(SYMCRYPT_TARGET_ENV WindowsUserMode)

# Define _X86_ to set up the correct SymCrypt macros, e.g. SYMCRYPT_CPU_X86
add_compile_options(-D_X86_)

# We link with modules that use the __stdcall calling convention for X86, but not all of the
# functions declarations are annotated to specify the calling convention. Thus, we have to
# set the default to __stdcall.
add_compile_options(/Gz)