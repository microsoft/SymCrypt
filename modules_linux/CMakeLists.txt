add_subdirectory(common) # Common functionality for Linux modules
add_subdirectory(generic) # Generic Linux module
if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64")
    add_subdirectory(oe_full) # OpenEnclave with all functionality
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64")
    add_subdirectory(embedded) # Embedded Linux module
endif()