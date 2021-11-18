add_subdirectory(linux_common) # Common functionality for Linux modules
add_subdirectory(generic_linux) # Generic Linux module
if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64")
    add_subdirectory(oe_full) # OpenEnclave with all functionality
endif()
add_subdirectory(embedded) # Embedded Linux module