set(SOURCES
    ../common/integrity.c
    ../common/optional/rngfipsjitter.c
    ../common/optional/rngsecureurandom.c)

include_directories(${CMAKE_SOURCE_DIR}/inc ../common ${CMAKE_SOURCE_DIR}/jitterentropy-library)

add_library(symcrypt_embedded SHARED ${SOURCES})

# Link jitterentropy and libatomic
target_link_libraries(symcrypt_embedded ${CMAKE_SOURCE_DIR}/jitterentropy-library/libjitterentropy.a pthread atomic)

set(TARGET_NAME symcrypt_embedded)
set(OUTPUT_DIR ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/embedded)
set(DO_FIPS_POSTPROCESSING True)

include(../common/ModuleCommon.cmake)