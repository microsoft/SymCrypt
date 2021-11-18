set(SOURCES
    ../linux_common/nointegrity.c
    ../linux_common/optional/rngfipsjitter.c
    ../linux_common/optional/rngsecureurandom.c)

include_directories(${CMAKE_SOURCE_DIR}/inc ../linux_common ${CMAKE_SOURCE_DIR}/jitterentropy-library)

add_library(symcrypt_linux SHARED ${SOURCES})

# Link jitterentropy
target_link_libraries(symcrypt_linux ${CMAKE_SOURCE_DIR}/jitterentropy-library/libjitterentropy.a pthread)

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

add_dependencies(symcrypt_linux symcrypt_linuxusermode symcrypt_common symcrypt_module_linux_common jitterentropy_lib)

set_target_properties(symcrypt_linux PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/generic_linux)
set_target_properties(symcrypt_linux PROPERTIES LIBRARY_OUTPUT_NAME "symcrypt")

if (CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_compile_options(-mllvm -x86-speculative-load-hardening)
endif()
