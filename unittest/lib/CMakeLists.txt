# Request C++17 standard to enable `if constexpr`
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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

# Need to include an asm file from here.
include_directories(${SYMCRYPT_SOURCE_DIR}/lib)

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
