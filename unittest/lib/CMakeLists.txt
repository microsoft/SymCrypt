set(SOURCES
    main.cpp
    testAesCtrDrbg.cpp
    kat.cpp
    rng.cpp
    perfPrint.cpp
    printtable.cpp
    resultMerge.cpp
    sc_implementations.cpp
    ref_implementations.cpp
    testhash.cpp
    testSelftest.cpp
    testMac.cpp
    testBlockCiphers.cpp
    testXts.cpp
    testAuthEnc.cpp
    testStreamCipher.cpp
    testWipe.cpp
    testutil.cpp
    testKdf.cpp
    testTlsCbcHmac.cpp
    env_SymCryptUnittest.cpp
    testMultiThread.cpp
    rndDriver.cpp
    testArithmetic.cpp
    testEcc.cpp
    callback.cpp
    testMontgomery.cpp
    testRsaSign.cpp
    testRsaEnc.cpp
    testDh.cpp
    testDsa.cpp
    testScsTable.cpp
    testScsTools.cpp
    testIEEE802_11SaeCustom.cpp
    perf.cpp
  )

# Append Windows-specific sources
if(WIN32)
    list(APPEND SOURCES
        rsa32_implementations.cpp
        capi_implementations.cpp
        cng_implementations.cpp
        msbignum_implementations.cpp
        # testInterop.cpp
        # testRsa.cpp
        # testRsa_sc.cpp
        # testRsa_msbignum.cpp
        # testRsa_cng.cpp
        # testDl.cpp
        # testDl_sc.cpp
        # testDl_msbignum.cpp
        # testDl_cng.cpp
    )
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64")
    list(APPEND SOURCES amd64/saveymm.asm)
    set_source_files_properties(amd64/saveymm.asm PROPERTY LANGUAGE ASM_MASM)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "X86")
    list(APPEND SOURCES i386/savexmm.asm)
    set_source_files_properties(i386/savexmm.asm PROPERTY LANGUAGE ASM_MASM)
endif()

# Need to include an asm file from here.
include_directories(${CMAKE_SOURCE_DIR}/lib)
include_directories(${CMAKE_SOURCE_DIR}/SymCryptDependencies/inc)
include_directories(../inc)

if(WIN32)
    # DNDEBUG is required to link with msbignum. This should eventually be removed.
    add_compile_options(-DNDEBUG)
    add_compile_options(-D_CRT_SECURE_NO_WARNINGS)

    if(NOT SYMCRYPT_INTERNAL_BUILD)
        add_compile_options(-DINCLUDE_IMPL_MSBIGNUM=0)
        add_compile_options(-DINCLUDE_IMPL_RSA32=0)
    endif()
else()
    add_compile_options(-Wno-write-strings)
    add_compile_options(-DINCLUDE_IMPL_CAPI=0)
    add_compile_options(-DINCLUDE_IMPL_CNG=0)
    add_compile_options(-DINCLUDE_IMPL_MSBIGNUM=0)
    add_compile_options(-DINCLUDE_IMPL_RSA32=0)
endif()

add_library(symcryptunittest_lib STATIC ${SOURCES})
set_target_properties(symcryptunittest_lib PROPERTIES PREFIX "")
