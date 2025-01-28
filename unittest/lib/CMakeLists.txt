set(SOURCES
    callback.cpp
    kat.cpp
    main.cpp
    perf.cpp
    perfPrint.cpp
    printtable.cpp
    ref_implementations.cpp
    resultMerge.cpp
    rndDriver.cpp
    rng.cpp
    sc_implementations.cpp
    testAesCtrDrbg.cpp
    testArithmetic.cpp
    testAuthEnc.cpp
    testBlockCiphers.cpp
    testCustomizableXof.cpp
    testDh.cpp
    testDsa.cpp
    testEcc.cpp
    testhash.cpp
    testHbs.cpp
    testKdf.cpp
    testKem.cpp
    testKeyWrap.cpp
    testKmac.cpp
    testMac.cpp
    testMontgomery.cpp
    testMultiThread.cpp
    testPaddingPkcs7.cpp
    testRsaEnc.cpp
    testRsaSign.cpp
    testPqDsa.cpp
    testScsTable.cpp
    testScsTools.cpp
    testSelftest.cpp
    testServiceIndicator.cpp
    testStatusIndicator.cpp
    testStreamCipher.cpp
    testTlsCbcHmac.cpp
    testutil.cpp
    testWipe.cpp
    testXof.cpp
    testXts.cpp
  )

# Append Windows-specific sources
if(WIN32)
    list(APPEND SOURCES
        env_windowsSymCryptUnittest.cpp
        rsa32_implementations.cpp
        capi_implementations.cpp
        cng_implementations.cpp
        msbignum_implementations.cpp
        testIEEE802_11SaeCustom.cpp
    )
else()
    list(APPEND SOURCES
        env_linuxSymCryptUnittest.cpp
    )
endif()

if(WIN32 AND SYMCRYPT_USE_ASM)
    if(SYMCRYPT_TARGET_ARCH MATCHES "AMD64")
        list(APPEND SOURCES amd64/savevectors.asm)
        set_source_files_properties(amd64/savevectors.asm PROPERTIES LANGUAGE ASM_MASM)
    elseif(SYMCRYPT_TARGET_ARCH MATCHES "X86")
        list(APPEND SOURCES i386/savevectors.asm)
        set_source_files_properties(i386/savevectors.asm PROPERTIES LANGUAGE ASM_MASM)
        set_source_files_properties(i386/savevectors.asm PROPERTIES COMPILE_OPTIONS "/safeseh")
    endif()
elseif(SYMCRYPT_USE_ASM) # Linux
    if(SYMCRYPT_TARGET_ARCH MATCHES "AMD64")
        list(APPEND SOURCES amd64/saveymm-gas.asm)
        set_source_files_properties(amd64/saveymm-gas.asm PROPERTIES LANGUAGE ASM)
    endif()
endif()

if(SYMCRYPT_TEST_WITH_OPENSSL)
    list(APPEND SOURCES
        openssl_implementations.cpp
    )
endif()

if(SYMCRYPT_TEST_LIBCRUX)
    list(APPEND SOURCES
        libcrux_implementations.cpp
    )
endif()

if(WIN32)
    # NDEBUG is required to link with msbignum. This should eventually be removed.
    add_compile_definitions(NDEBUG)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wno-write-strings)
    add_compile_definitions(INCLUDE_IMPL_CAPI=0)
    add_compile_definitions(INCLUDE_IMPL_CNG=0)
    add_compile_definitions(INCLUDE_IMPL_MSBIGNUM=0)
    add_compile_definitions(INCLUDE_IMPL_RSA32=0)
endif()

if(SYMCRYPT_TARGET_ARCH STREQUAL "ARM" AND CMAKE_C_COMPILER_ID MATCHES "GNU")
    # Hide warning due to abi change.
    set_source_files_properties(kat.cpp PROPERTIES COMPILE_OPTIONS "-Wno-psabi")
    set_source_files_properties(perf.cpp PROPERTIES COMPILE_OPTIONS "-Wno-psabi")
endif()

add_library(symcryptunittest_lib STATIC ${SOURCES})
set_target_properties(symcryptunittest_lib PROPERTIES PREFIX "")

if(SYMCRYPT_TEST_WITH_OPENSSL)
    target_include_directories(symcryptunittest_lib PRIVATE ${OPENSSL_INCLUDE_DIR})
endif()

if(SYMCRYPT_TEST_LIBCRUX)
    target_include_directories(symcryptunittest_lib PRIVATE ${SYMCRYPT_SOURCE_DIR}/3rdparty/hacl-packages/libcrux/include)
    target_include_directories(symcryptunittest_lib PRIVATE ${SYMCRYPT_SOURCE_DIR}/3rdparty/hacl-packages/karamel/include)
endif()
