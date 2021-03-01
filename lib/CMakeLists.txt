set(SOURCES_COMMON
    blockciphermodes.c
    hash.c
    parhash.c
    ccm.c
    ghash.c
    gcm.c
    aes-default.c
    aes-default-bc.c
    aes-key.c
    aes-c.c
    aes-asm.c
    aes-xmm.c
    aes-neon.c
    aes-selftest.c
    AesTables.c
    aescmac.c
    xtsaes.c
    3des.c
    DesTables.c
    desx.c
    rc2.c
    rc4.c
    sha1.c
    sha256.c
    sha512.c
    md5.c
    md4.c
    md2.c
    hmacmd5.c
    hmacsha1.c
    hmacsha256.c
    hmacsha384.c
    hmacsha512.c
    tlsCbcVerify.c
    aesCtrDrbg.c
    libmain.c
    equal.c
    FatalIntercept.c
    selftest.c
    rdrand.c
    rdseed.c
    sha256Par.c
    sha512par.c
    marvin32.c
    cpuid.c
    cpuid_um.c
    cpuid_notry.c
    pbkdf2.c
    pbkdf2_hmacsha1.c
    pbkdf2_hmacsha256.c
    sp800_108.c
    sp800_108_hmacsha1.c
    sp800_108_hmacsha256.c
    tlsprf.c
    tlsprf_selftest.c
    hkdf.c
    hkdf_selftest.c
    chacha20.c
    poly1305.c
    chacha20_poly1305.c
    a_dispatch.c
    fdef_general.c
    fdef_int.c
    fdef_mod.c
    fdef369_mod.c
    ecpoint.c
    ecurve.c
    eckey.c
    ec_dispatch.c
    ec_short_weierstrass.c
    ec_internal_curves.c
    ec_dsa.c
    ec_dh.c
    ec_montgomery.c
    ec_twisted_edwards.c
    ec_mul.c
    ScsTable.c
    scsTools.c
    primes.c
    modexp.c
    gen_int.c
    crt.c
    rsakey.c
    rsa_enc.c
    rsa_padding.c
    dlgroup.c
    dlkey.c
    dsa.c
    dh.c
    dl_internal_groups.c
    recoding.c
    IEEE802_11SaeCustom.c
  )

if(NOT WIN32)
    list(APPEND SOURCES_COMMON linux/intrinsics.c)
    list(APPEND SOURCES_COMMON linux/asmstubs.c)
endif()

if(WIN32 AND NOT(SYMCRYPT_TARGET_ENV MATCHES "Generic"))
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64")
        list(APPEND SOURCES_COMMON
            amd64/aesasm.asm
            amd64/fdef_asm.asm
            amd64/fdef_mulx.asm
            amd64/fdef369_asm.asm
            amd64/sha1asm.asm
            amd64/wipe.asm)
        set_source_files_properties(
            amd64/aesasm.asm
            amd64/fdef_asm.asm
            amd64/fdef_mulx.asm
            amd64/fdef369_asm.asm
            amd64/sha1asm.asm
            amd64/wipe.asm
            PROPERTY LANGUAGE ASM_MASM)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "X86")
        list(APPEND SOURCES_COMMON
            i386/aesasm.asm
            i386/fdef_asm.asm
            i386/rc4asm.asm
            i386/sha1asm.asm
            i386/wipe.asm)
        set_source_files_properties(
            i386/aesasm.asm
            i386/fdef_asm.asm
            i386/rc4asm.asm
            i386/sha1asm.asm
            i386/wipe.asm
            PROPERTY LANGUAGE ASM_MASM)
    endif()
endif()

include_directories(${CMAKE_SOURCE_DIR}/inc)

add_library(symcrypt_common STATIC ${SOURCES_COMMON})

if(WIN32)
    add_library(symcrypt_usermodewin7 STATIC env_windowsUserModeWin7.c)
    set_target_properties(symcrypt_usermodewin7 PROPERTIES PREFIX "")
    target_link_libraries(symcrypt_usermodewin7 symcrypt_common)

    add_library(symcrypt_usermodewin8_1 STATIC env_windowsUserModeWin8_1.c)
    set_target_properties(symcrypt_usermodewin8_1 PROPERTIES PREFIX "")
    target_link_libraries(symcrypt_usermodewin8_1 symcrypt_common)

    # add_library(symcrypt_kernelmodewin7 STATIC env_windowsKernelModeWin7.c)
    # set_target_properties(symcrypt_kernelmodewin7 PROPERTIES PREFIX "")
    # target_link_libraries(symcrypt_kernelmodewin7 symcrypt_common)

    # add_library(symcrypt_kernelmodewin8_1 STATIC env_windowsKernelModeWin8_1.c)
    # set_target_properties(symcrypt_kernelmodewin8_1 PROPERTIES PREFIX "")
    # target_link_libraries(symcrypt_kernelmodewin8_1 symcrypt_common)

    # add_library(symcrypt_windowsbootlib STATIC env_windowsBootLib.c)
    # set_target_properties(symcrypt_windowsbootlib PROPERTIES PREFIX "")
    # target_link_libraries(symcrypt_windowsbootlib symcrypt_common)

    add_library(symcrypt_windowskerneldebugger STATIC env_windowsKernelDebugger.c)
    set_target_properties(symcrypt_windowskerneldebugger PROPERTIES PREFIX "")
    target_link_libraries(symcrypt_windowskerneldebugger symcrypt_common)

    add_library(symcrypt_windows10sgx STATIC env_win10Sgx.c)
    set_target_properties(symcrypt_windows10sgx PROPERTIES PREFIX "")
    target_link_libraries(symcrypt_windows10sgx symcrypt_common)
endif()

set(SOURCES_GENERIC ${SOURCES_COMMON})
list(APPEND SOURCES_GENERIC env_generic.c)
if(NOT WIN32)
    add_compile_options(-Wno-trigraphs)
endif()
add_library(symcrypt_generic STATIC env_generic.c)
set_target_properties(symcrypt_generic PROPERTIES PREFIX "")
target_link_libraries(symcrypt_generic symcrypt_common)
