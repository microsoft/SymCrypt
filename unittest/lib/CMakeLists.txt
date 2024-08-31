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
    testXof.cpp
    testCustomizableXof.cpp
    testKmac.cpp
    testBlockCiphers.cpp
    testXts.cpp
    testAuthEnc.cpp
    testStreamCipher.cpp
    testWipe.cpp
    testutil.cpp
    testKdf.cpp
    testTlsCbcHmac.cpp
    testMultiThread.cpp
    rndDriver.cpp
    testArithmetic.cpp
    testEcc.cpp
    callback.cpp
    testKem.cpp
    testMontgomery.cpp
    testRsaSign.cpp
    testRsaEnc.cpp
    testDh.cpp
    testDsa.cpp
    testScsTable.cpp
    testScsTools.cpp
    perf.cpp
    testPaddingPkcs7.cpp
    testStatusIndicator.cpp
    testHbs.cpp
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
target_link_libraries(symcryptunittest_lib symcrypt_common)

if(SYMCRYPT_TEST_WITH_OPENSSL)
    target_include_directories(symcryptunittest_lib PRIVATE ${OPENSSL_INCLUDE_DIR})
endif()

if(SYMCRYPT_TEST_LIBCRUX)
    target_include_directories(symcryptunittest_lib PRIVATE ${SYMCRYPT_SOURCE_DIR}/3rdparty/hacl-packages/libcrux/include)
    target_include_directories(symcryptunittest_lib PRIVATE ${SYMCRYPT_SOURCE_DIR}/3rdparty/hacl-packages/karamel/include)
endif()
