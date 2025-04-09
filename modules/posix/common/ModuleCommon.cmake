# Common build steps for all SymCrypt Posix modules
# Set the following variables before including this file:
#
# TARGET_NAME - name of the target being built. This should be the same value given to add_library
# OUTPUT_DIR - the directory to output the module to

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
if(SYMCRYPT_TARGET_ARCH MATCHES ARM AND NOT CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64")
    set(STRIP_COMMAND ${TARGET_TRIPLE}-strip)
    set(OBJCOPY_COMMAND ${TARGET_TRIPLE}-objcopy)
else()
    set(STRIP_COMMAND strip)
    set(OBJCOPY_COMMAND objcopy)
endif()

if (CMAKE_SYSTEM_NAME MATCHES "Darwin")
  target_link_options(${TARGET_NAME} PRIVATE
    -Wl,-all_load
    $<TARGET_FILE:symcrypt_module_posix_common>
    $<TARGET_FILE:symcrypt_posixusermode>
    $<TARGET_FILE:symcrypt_common>
    -nostdlib
    -nodefaultlibs
    -nostartfiles
    -Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/../common/exports.osx
  )
  if(SYMCRYPT_TARGET_ARCH MATCHES "AMD64" AND SYMCRYPT_USE_ASM)
    target_link_options(${TARGET_NAME} PRIVATE
      -Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/../common/exports.osx.x86_64
    )
  endif()
else()
  target_link_options(${TARGET_NAME} PRIVATE
    -Wl,--whole-archive
    $<TARGET_FILE:symcrypt_module_posix_common>
    $<TARGET_FILE:symcrypt_posixusermode>
    $<TARGET_FILE:symcrypt_common>
    -Wl,--no-whole-archive
    -Wl,-Bsymbolic
    -Wl,-z,relro
    -Wl,-z,noexecstack
    -Wl,-z,now
    -Wl,-gc-sections
    -Wl,--build-id
    -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../common/exports.ver
    -nostdlib
    -nodefaultlibs
    -nostartfiles
  )
endif()

add_dependencies(${TARGET_NAME} symcrypt_posixusermode symcrypt_common symcrypt_module_posix_common)

if(SYMCRYPT_TARGET_ARCH MATCHES "AMD64" AND
    CMAKE_C_COMPILER_ID MATCHES "Clang" AND
    NOT CMAKE_BUILD_TYPE MATCHES "Debug|Sanitize")
    # Spectre/Meltdown mitigations - these cause segfaults on AMD64 debug due to a Clang bug
    # https://github.com/llvm/llvm-project/issues/93898
    add_compile_options(-mllvm -x86-speculative-load-hardening)
endif()

set_target_properties(${TARGET_NAME} PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_DIR})
set_target_properties(${TARGET_NAME} PROPERTIES LIBRARY_OUTPUT_NAME "symcrypt")
set_target_properties(${TARGET_NAME} PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(${TARGET_NAME} PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})


if(CMAKE_BUILD_TYPE MATCHES "Release|RelWithDebInfo" AND SYMCRYPT_STRIP_BINARY AND NOT CMAKE_SYSTEM_NAME MATCHES "Darwin")
    add_custom_command(
        TARGET ${TARGET_NAME}
        POST_BUILD
        COMMAND mkdir -p $<TARGET_FILE_DIR:${TARGET_NAME}>/.debug
        COMMAND ${OBJCOPY_COMMAND} --only-keep-debug $<TARGET_FILE:${TARGET_NAME}> $<TARGET_FILE_DIR:${TARGET_NAME}>/.debug/$<TARGET_FILE_NAME:${TARGET_NAME}>
        COMMAND ${STRIP_COMMAND} --strip-unneeded ${KEEP_SYMBOL_ARGS} $<TARGET_FILE:${TARGET_NAME}>
        COMMENT "Splitting and stripping binary for release build"
        COMMAND_EXPAND_LISTS
    )
endif()

if(SYMCRYPT_FIPS_BUILD AND SYMCRYPT_FIPS_POSTPROCESS)
    add_custom_command(
        TARGET ${TARGET_NAME}
        POST_BUILD
        COMMAND mkdir -p $<TARGET_FILE_DIR:${TARGET_NAME}>/processing
        COMMAND ${Python3_EXECUTABLE} ${SYMCRYPT_SOURCE_DIR}/scripts/process_fips_module.py $<TARGET_FILE:${TARGET_NAME}> -d
        COMMENT "Postprocessing SymCrypt shared object for FIPS integrity verification"
    )
endif()
