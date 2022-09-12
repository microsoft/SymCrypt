add_subdirectory(common) # Common functionality for Linux modules
add_subdirectory(generic) # Generic Linux module
if(SYMCRYPT_TARGET_ARCH MATCHES "AMD64")
    add_subdirectory(oe_full) # OpenEnclave with all functionality
endif()