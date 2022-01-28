set(SOURCES
    ../common/optional/rngfipsjitter.c
    ../common/optional/rngsecureurandom.c)

# Enable integrity verification if compiling for AMD64 or ARM64
if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64")
    list(APPEND SOURCES ../common/integrity.c)
    set(DO_FIPS_POSTPROCESSING True)
else()
    list(APPEND SOURCES ../common/nointegrity.c)
endif()

include_directories(${CMAKE_SOURCE_DIR}/inc ../common ${CMAKE_SOURCE_DIR}/jitterentropy-library)

add_library(symcrypt_generic_linux SHARED ${SOURCES})

# Link jitterentropy
target_link_libraries(symcrypt_generic_linux ${CMAKE_SOURCE_DIR}/jitterentropy-library/libjitterentropy.a pthread)

set(TARGET_NAME symcrypt_generic_linux)
set(OUTPUT_DIR ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/generic)

include(../common/ModuleCommon.cmake)