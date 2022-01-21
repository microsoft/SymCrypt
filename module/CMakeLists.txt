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

add_subdirectory(linux_common) # Common functionality for Linux modules
add_subdirectory(generic_linux) # Generic Linux module
if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64")
    add_subdirectory(oe_full) # OpenEnclave with all functionality
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64")
    add_subdirectory(embedded) # Embedded Linux module
endif()