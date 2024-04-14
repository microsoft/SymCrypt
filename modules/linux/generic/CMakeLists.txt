set(SOURCES
    statusindicator.c
    ../common/optional/rngfipsjitter.c
    ../common/optional/rngforkdetection.c
    ../common/optional/rngsecureurandom.c
    ../common/optional/module_linuxUserMode.c
    ../common/callbacks_pthread.c)

# Enable integrity verification if compiling for AMD64 or ARM64 or ARM
if(SYMCRYPT_TARGET_ARCH MATCHES "AMD64|ARM")
    list(APPEND SOURCES ../common/integrity.c)
else()
    list(APPEND SOURCES ../common/nointegrity.c)
endif()

include_directories(${SYMCRYPT_SOURCE_DIR}/inc ../common ${SYMCRYPT_SOURCE_DIR}/3rdparty/jitterentropy-library)

add_library(symcrypt_generic_linux SHARED ${SOURCES})

# Link jitterentropy and libatomic
target_link_libraries(symcrypt_generic_linux ${SYMCRYPT_SOURCE_DIR}/3rdparty/jitterentropy-library/libjitterentropy.a pthread atomic)

add_dependencies(symcrypt_generic_linux jitterentropy_lib)

set(TARGET_NAME symcrypt_generic_linux)
set(OUTPUT_DIR ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/generic)

include(../common/ModuleCommon.cmake)