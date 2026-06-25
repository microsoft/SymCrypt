set(SOURCES_COMMON
    ec_encoding.c
    hpke.c
    hpke_aead.c
    hpke_kdf.c
    hpke_kem.c
    hpke_kem_dhkem.c
)

add_library(symcrypt_plus STATIC ${SOURCES_COMMON})

target_include_directories(symcrypt_plus PUBLIC
    ${SYMCRYPT_SOURCE_DIR}/inc
    ${SYMCRYPT_SOURCE_DIR}/inc/symcrypt_plus
)

# symcrypt_plus depends on symcrypt for primitives
target_link_libraries(symcrypt_plus PUBLIC symcrypt_common)

# Need access to local internal headers (hpke_internal.h, precomp.h)
target_include_directories(symcrypt_plus PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
