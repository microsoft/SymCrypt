if((SYMCRYPT_TARGET_ENV MATCHES "PosixUserMode") AND NOT (CMAKE_BUILD_TYPE MATCHES "Sanitize" AND SYMCRYPT_FIPS_BUILD))
    # Module integrity check is seen as OOB access by sanitizers, and sanitizer instrumentation
    # breaks integrity check assumptions. Only enable FIPS module when not running with sanitizers
    add_subdirectory(posix)
endif()

if(WIN32)
    add_subdirectory(windows)
endif()
