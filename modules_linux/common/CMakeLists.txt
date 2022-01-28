set(SOURCES
    module.c
    rng.c)

include_directories(${CMAKE_SOURCE_DIR}/inc)

add_library(symcrypt_module_linux_common STATIC ${SOURCES})

set(jitter_compiler_AMD64 env CC=gcc)
set(jitter_compiler_ARM64 env CC=aarch64-linux-gnu-gcc)
set(jitter_cflags "-fwrapv --param ssp-buffer-size=4 -fvisibility=hidden -fPIE -Wcast-align -Wmissing-field-initializers -Wshadow -Wswitch-enum -fno-plt")
add_custom_target(jitterentropy_lib ALL
  COMMAND make clean
  COMMAND ${CMAKE_COMMAND} -E ${jitter_compiler_${CMAKE_SYSTEM_PROCESSOR}} env "CFLAGS=${jitter_cflags}" make
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/jitterentropy-library
)