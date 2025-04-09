set(SOURCES
    statusindicator.c
    ../common/optional/rngforkdetection.c
    ../common/optional/rngsecureurandom.c
    ../common/optional/module_posixUserMode.c
    ../common/callbacks_pthread.c)

# Enable integrity verification if compiling for AMD64 or ARM64 or ARM
if(SYMCRYPT_TARGET_ARCH MATCHES "AMD64|ARM")
    list(APPEND SOURCES ../common/integrity.c)
else()
    list(APPEND SOURCES ../common/nointegrity.c)
endif()

if(SYMCRYPT_FIPS_BUILD)
    list(APPEND SOURCES ../common/optional/rngfipsjitter.c)
endif()

include_directories(${SYMCRYPT_SOURCE_DIR}/inc ../common ${SYMCRYPT_SOURCE_DIR}/3rdparty/jitterentropy-library)

add_library(symcrypt_generic_posix SHARED ${SOURCES})

if(SYMCRYPT_FIPS_BUILD)
    # Link jitterentropy
    target_link_libraries(symcrypt_generic_posix ${SYMCRYPT_SOURCE_DIR}/3rdparty/jitterentropy-library/libjitterentropy.a)
    add_dependencies(symcrypt_generic_posix jitterentropy_lib)
endif()

# Link pthread and libatomic
target_link_libraries(symcrypt_generic_posix pthread)
if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    target_link_libraries(symcrypt_generic_posix atomic)
endif()

set(TARGET_NAME symcrypt_generic_posix)
set(OUTPUT_DIR ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/generic)

include(../common/ModuleCommon.cmake)
