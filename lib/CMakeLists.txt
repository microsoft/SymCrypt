set(SOURCES
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
    recoding.c
    IEEE802_11SaeCustom.c
  )

include_directories(${CMAKE_SOURCE_DIR}/inc)
include_directories(../km)

set(SOURCES_GENERIC ${SOURCES})
list(APPEND SOURCES_GENERIC env_generic.c)

set(SOURCES_USERMODEWIN7 ${SOURCES})
list(APPEND SOURCES_USERMODEWIN7 env_windowsUserModeWin7.c)

set(SOURCES_USERMODEWIN8_1 ${SOURCES})
list(APPEND SOURCES_USERMODEWIN8_1 env_windowsUserModeWin8_1.c)

set(SOURCES_KERNELMODEWIN7 ${SOURCES})
list(APPEND SOURCES_KERNELMODEWIN7 env_windowsKernelModeWin7.c)

set(SOURCES_KERNELMODEWIN8_1 ${SOURCES})
list(APPEND SOURCES_KERNELMODEWIN8_1 env_windowsKernelModeWin8_1.c)

set(SOURCES_WINDOWSBOOTLIB ${SOURCES})
list(APPEND SOURCES_WINDOWSBOOTLIB env_windowsBootLib.c)

set(SOURCES_WINDOWSKERNELDEBUGGER ${SOURCES})
list(APPEND SOURCES_WINDOWSKERNELDEBUGGER env_windowsKernelDebugger.c)

set(SOURCES_WIN10SGX ${SOURCES})
list(APPEND SOURCES_WIN10SGX env_win10Sgx.c)

if(WIN32)
    add_library(symcrypt_usermodewin7 STATIC ${SOURCES_USERMODEWIN7})
    set_target_properties(symcrypt_usermodewin7 PROPERTIES PREFIX "")

    add_library(symcrypt_usermodewin8_1 STATIC ${SOURCES_USERMODEWIN8_1})
    set_target_properties(symcrypt_usermodewin8_1 PROPERTIES PREFIX "")

    # add_library(symcrypt_kernelmodewin7 STATIC ${SOURCES_KERNELMODEWIN7})
    # set_target_properties(symcrypt_kernelmodewin7 PROPERTIES PREFIX "")

    # add_library(symcrypt_kernelmodewin8_1 STATIC ${SOURCES_KERNELMODEWIN8_1})
    # set_target_properties(symcrypt_kernelmodewin8_1 PROPERTIES PREFIX "")

    # add_library(symcrypt_windowsbootlib STATIC ${SOURCES_WINDOWSBOOTLIB})
    # set_target_properties(symcrypt_windowsbootlib PROPERTIES PREFIX "")

    add_library(symcrypt_windowskerneldebugger STATIC ${SOURCES_WINDOWSKERNELDEBUGGER})
    set_target_properties(symcrypt_windowskerneldebugger PROPERTIES PREFIX "")

    add_library(symcrypt_windows10sgx STATIC ${SOURCES_WIN10SGX})
    set_target_properties(symcrypt_windows10sgx PROPERTIES PREFIX "")
else()
    list(FILTER SOURCES_GENERIC EXCLUDE REGEX aes-asm.c)
    list(FILTER SOURCES_GENERIC EXCLUDE REGEX aes-neon.c)
    list(FILTER SOURCES_GENERIC EXCLUDE REGEX aes-xmm.c)
    add_compile_options(-Wno-trigraphs)
endif()

add_library(symcrypt_generic STATIC ${SOURCES_GENERIC})
set_target_properties(symcrypt_generic PROPERTIES PREFIX "")
