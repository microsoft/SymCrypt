set(SOURCES
    module.c)

include_directories(${CMAKE_SOURCE_DIR}/inc ../linux_common)

add_library(symcrypt SHARED ${SOURCES})

target_link_options(symcrypt PRIVATE
  -Wl,--whole-archive
  $<TARGET_FILE:symcrypt_module_linux_common>
  $<TARGET_FILE:symcrypt_linuxusermode>
  $<TARGET_FILE:symcrypt_common>
  -Wl,--no-whole-archive
  -Wl,-Bsymbolic
  -Wl,-z,noexecstack
  -Wl,-z,now
  -Wl,-gc-sections
  -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports.ver
  -nostdlib
  -nodefaultlibs
  -nostartfiles
)

add_dependencies(symcrypt symcrypt_linuxusermode symcrypt_common symcrypt_module_linux_common)

add_custom_target(
  symcrypt_fips ALL
  COMMAND ${CMAKE_SOURCE_DIR}/scripts/process_fips_module.py $<TARGET_FILE:symcrypt> -d
  DEPENDS $<TARGET_FILE:symcrypt>
  COMMENT "Postprocessing SymCrypt shared object for FIPS integrity verification"
)

#   -Wl,--no-undefined,-Bstatic,-Bsymbolic,--export-dynamic,-pie,--build-id