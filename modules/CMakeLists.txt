if(CMAKE_SYSTEM_NAME MATCHES "Linux" AND NOT CMAKE_BUILD_TYPE MATCHES Sanitize)
    # Module integrity check is seen as OOB access by sanitizers, and sanitizer instrumentation
    # breaks integrity check assumptions. Only enable module when not running with sanitizers
    add_subdirectory(linux)
endif()

if(WIN32)
    add_subdirectory(windows)
endif()
