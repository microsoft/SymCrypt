set(SOURCES
    module.c)

include_directories(${CMAKE_SOURCE_DIR}/inc ../linux_common)

add_library(symcrypt_linux SHARED ${SOURCES})

target_link_options(symcrypt_linux PRIVATE
  -Wl,--whole-archive
  $<TARGET_FILE:symcrypt_module_linux_common>
  $<TARGET_FILE:symcrypt_linuxusermode>
  $<TARGET_FILE:symcrypt_common>
  -Wl,--no-whole-archive
  -Wl,-Bsymbolic
  -Wl,-z,noexecstack
  -Wl,-z,now
  -Wl,-gc-sections
  -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../linux_common/exports.ver
  -nostartfiles
)

add_dependencies(symcrypt_linux symcrypt_linuxusermode symcrypt_common symcrypt_module_linux_common)

set_target_properties(symcrypt_linux PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/generic_linux)
set_target_properties(symcrypt_linux PROPERTIES LIBRARY_OUTPUT_NAME "symcrypt")

if (CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_compile_options(-mllvm -x86-speculative-load-hardening)
endif()
