set(SOURCES
    module.c
    symcrypt.def
    symcrypt.rc)

include_directories(${SYMCRYPT_SOURCE_DIR}/inc)

add_library(symcrypt_usermode_dll SHARED ${SOURCES})

target_link_libraries(symcrypt_usermode_dll symcrypt_usermodewin8_1 bcrypt.lib ntdll.lib)

add_dependencies(symcrypt_usermode_dll symcrypt_usermodewin8_1)

set_target_properties(symcrypt_usermode_dll PROPERTIES
    OUTPUT_NAME "symcrypt"
    PREFIX ""
    SUFFIX ".dll"
    IMPORT_SUFFIX ".lib")