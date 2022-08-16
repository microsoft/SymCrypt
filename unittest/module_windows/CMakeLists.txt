set(SOURCES
    module.cpp
    exports.def
    )

add_compile_options(-DINCLUDE_IMPL_MSBIGNUM=0)
add_compile_options(-DINCLUDE_IMPL_RSA32=0)

add_library(symcrypttestmodule SHARED ${SOURCES})

target_link_libraries(symcrypttestmodule symcrypt_common symcrypt_usermodewin8_1 bcrypt)