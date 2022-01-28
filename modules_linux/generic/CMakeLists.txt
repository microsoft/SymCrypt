set(SOURCES
    ../common/nointegrity.c
    ../common/optional/rngfipsjitter.c
    ../common/optional/rngsecureurandom.c)

include_directories(${CMAKE_SOURCE_DIR}/inc ../common ${CMAKE_SOURCE_DIR}/jitterentropy-library)

add_library(symcrypt_generic_linux SHARED ${SOURCES})

# Link jitterentropy
target_link_libraries(symcrypt_generic_linux ${CMAKE_SOURCE_DIR}/jitterentropy-library/libjitterentropy.a pthread)

set(TARGET_NAME symcrypt_generic_linux)
set(OUTPUT_DIR ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/generic)

include(../common/ModuleCommon.cmake)