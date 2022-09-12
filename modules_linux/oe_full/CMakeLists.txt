set(SOURCES
    ../common/integrity.c
    rng.c)

include_directories(${CMAKE_SOURCE_DIR}/inc ../common)

add_library(symcrypt_oe SHARED ${SOURCES})

set(TARGET_NAME symcrypt_oe)
set(OUTPUT_DIR ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/oe_full)

include(../common/ModuleCommon.cmake)