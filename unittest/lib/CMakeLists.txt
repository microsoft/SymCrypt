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
    testScsTable.cpp
    testScsTools.cpp
    testIEEE802_11SaeCustom.cpp
  )

# Append Windows-specific sources
if(WIN32)
    list(APPEND SOURCES
        rsa32_implementations.cpp
        capi_implementations.cpp
        cng_implementations.cpp
        msbignum_implementations.cpp
        perf.cpp
        testInterop.cpp
        # testRsa.cpp
        # testRsa_sc.cpp
        # testRsa_msbignum.cpp
        # testRsa_cng.cpp
        testDl.cpp
        testDl_sc.cpp
        testDl_msbignum.cpp
        testDl_cng.cpp
    )
endif()

# Need to include an asm file from here.
include_directories(${CMAKE_SOURCE_DIR}/lib)
include_directories(${CMAKE_SOURCE_DIR}/SymCryptDependencies/inc)

if(WIN32)
    # DNDEBUG is required to link with msbignum. This should eventually be removed.
    add_compile_options(-DNDEBUG)
    # Workaround for including ntintsafe.h
    add_compile_options(-DCMAKE_COMPILE)
    add_compile_options(-D_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wno-write-strings)
endif()

add_library(symcryptunittest_lib STATIC ${SOURCES})
set_target_properties(symcryptunittest_lib PROPERTIES PREFIX "")
