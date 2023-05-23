if(NOT WIN32 AND NOT CMAKE_BUILD_TYPE MATCHES Sanitize)
    # Module integrity check is seen as OOB access by sanitizers, and sanitizer instrumentation
    # breaks integrity check assumptions. Only enable module when not running with sanitizers
    add_subdirectory(linux)
endif()

# Placeholder: CMake can't build Windows kernel drivers, and we don't currently have a
# Windows user-mode DLL
# if(WIN32)
#     add_subdirectory(windows)
# endif()
