# Common build steps for all SymCrypt Linux modules
# Set the following variables before including this file:
#
# TARGET_NAME - name of the target being built. This should be the same value given to add_library
# OUTPUT_DIR - the directory to output the module to
# DO_FIPS_POSTPROCESSING - optional, set to true if the module uses FIPS integrity verification and
#     needs to be run through the FIPS postprocessing Python script.

# For release builds, we strip the modules of symbols except for the following symbols which are
# required by the FIPS post-processing script. On some systems, symbol stripping would normally
# be done at package install time, but our modules must be stripped before being run through the
# FIPS post-processing script or the the runtime integrity verification will not work. Although
# the symbol table is not in a loadable segment and is therefore not part of our FIPS boundary,
# stripping symbols changes size and offset information stored in the ELF header, which is
# within the FIPS boundary and therefore affects the result of the integrity check.
set(KEEP_SYMBOL_ARGS
    "-K" "SymCryptVolatileFipsHmacKey"
    "-K" "SymCryptVolatileFipsHmacKeyRva"
    "-K" "SymCryptVolatileFipsBoundaryOffset"
    "-K" "SymCryptVolatileFipsHmacDigest"
)

# Determine the which executable to use for stripping binaries
if(CMAKE_SYSTEM_PROCESSOR MATCHES ARM64 AND NOT CMAKE_HOST_SYSTEM_PROCESSOR MATCHES ARM64|aarch64)
    set(STRIP_COMMAND ${TARGET_TRIPLE}-strip)
else()
    set(STRIP_COMMAND strip)
endif()

target_link_options(${TARGET_NAME} PRIVATE
  -Wl,--whole-archive
  $<TARGET_FILE:symcrypt_module_linux_common>
  $<TARGET_FILE:symcrypt_linuxusermode>
  $<TARGET_FILE:symcrypt_common>
  -Wl,--no-whole-archive
  -Wl,-Bsymbolic
  -Wl,-z,noexecstack
  -Wl,-z,now
  -Wl,-gc-sections
  -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../common/exports.ver
  -nostdlib
  -nodefaultlibs
  -nostartfiles
)

add_dependencies(${TARGET_NAME} symcrypt_linuxusermode symcrypt_common symcrypt_module_linux_common)

if (CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_compile_options(-mllvm -x86-speculative-load-hardening)
endif()

set_target_properties(${TARGET_NAME} PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_DIR})
set_target_properties(${TARGET_NAME} PROPERTIES LIBRARY_OUTPUT_NAME "symcrypt")
set_target_properties(${TARGET_NAME} PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(${TARGET_NAME} PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})


if(CMAKE_BUILD_TYPE MATCHES Release)
  add_custom_command(
      TARGET ${TARGET_NAME}
      POST_BUILD
      COMMAND cp $<TARGET_FILE:${TARGET_NAME}> $<TARGET_FILE:${TARGET_NAME}>.debug
      COMMAND ${STRIP_COMMAND} --strip-unneeded ${KEEP_SYMBOL_ARGS} $<TARGET_FILE:${TARGET_NAME}>
      COMMENT "Stripping binary for release build"
      COMMAND_EXPAND_LISTS
  )
endif()

if(DO_FIPS_POSTPROCESSING)
    add_custom_command(
    TARGET ${TARGET_NAME}
    POST_BUILD
    COMMAND python3 ${CMAKE_SOURCE_DIR}/scripts/process_fips_module.py $<TARGET_FILE:${TARGET_NAME}> -d
    COMMENT "Postprocessing SymCrypt shared object for FIPS integrity verification"
    )
endif()
