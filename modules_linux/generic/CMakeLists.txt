set(SOURCES
    ../common/optional/rngfipsjitter.c
    ../common/optional/rngforkdetection.c
    ../common/optional/rngsecureurandom.c)

# Enable integrity verification if compiling for AMD64 or ARM64
if(SYMCRYPT_TARGET_ARCH MATCHES "AMD64|ARM64")
    list(APPEND SOURCES ../common/integrity.c)
else()
    list(APPEND SOURCES ../common/nointegrity.c)
endif()

include_directories(${CMAKE_SOURCE_DIR}/inc ../common ${CMAKE_SOURCE_DIR}/3rdparty/jitterentropy-library)

add_library(symcrypt_generic_linux SHARED ${SOURCES})

# Link jitterentropy and libatomic
target_link_libraries(symcrypt_generic_linux ${CMAKE_SOURCE_DIR}/3rdparty/jitterentropy-library/libjitterentropy.a pthread atomic)

set(TARGET_NAME symcrypt_generic_linux)
set(OUTPUT_DIR ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/generic)

include(../common/ModuleCommon.cmake)