set(SOURCES
    integrity.c)

include_directories(${CMAKE_SOURCE_DIR}/inc)

add_library(symcrypt_module_linux_common STATIC ${SOURCES})