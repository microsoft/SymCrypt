set(SOURCES
    ../linux_common/integrity.c
    rng.c)

include_directories(${CMAKE_SOURCE_DIR}/inc ../linux_common)

add_library(symcrypt_oe SHARED ${SOURCES})

target_link_options(symcrypt_oe PRIVATE
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
  -nostdlib
  -nodefaultlibs
  -nostartfiles
)

add_dependencies(symcrypt_oe symcrypt_linuxusermode symcrypt_common symcrypt_module_linux_common)

if (CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_compile_options(-mllvm -x86-speculative-load-hardening)
endif()

set_target_properties(symcrypt_oe PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/oe_full)
set_target_properties(symcrypt_oe PROPERTIES LIBRARY_OUTPUT_NAME "symcrypt")

add_custom_target(
  symcrypt_oe_fips ALL
  COMMAND python3 ${CMAKE_SOURCE_DIR}/scripts/process_fips_module.py $<TARGET_FILE:symcrypt_oe> -d
  DEPENDS $<TARGET_FILE:symcrypt_oe>
  COMMENT "Postprocessing SymCrypt shared object for FIPS integrity verification"
)

#   -Wl,--no-undefined,-Bstatic,-Bsymbolic,--export-dynamic,-pie,--build-id