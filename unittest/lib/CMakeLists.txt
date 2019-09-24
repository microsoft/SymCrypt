set(SOURCES
    main.cpp
    # symcryptunittest.rc
    testAesCtrDrbg.cpp
    kat.cpp
    rng.cpp
    perfprint.cpp
    printtable.cpp
    resultMerge.cpp
    sc_implementations.cpp
    # rsa32_implementations.cpp
    # capi_implementations.cpp
    # cng_implementations.cpp
    # msbignum_implementations.cpp
    ref_implementations.cpp
    testhash.cpp
    # perf.cpp
    testSelftest.cpp
    testMac.cpp
    testBlockCiphers.cpp
    testXts.cpp
    testAuthEnc.cpp
    testStreamCipher.cpp
    testWipe.cpp
    testUtil.cpp
    testKdf.cpp
    testTlsCbcHmac.cpp
    env_symcryptunittest.cpp
    testMultiThread.cpp
    rndDriver.cpp
    testArithmetic.cpp
    testEcc.cpp
    # testInterop.cpp
    # testRsa.cpp
    # testRsa_sc.cpp
    # testRsa_msbignum.cpp
    # testRsa_cng.cpp
    # testDl.cpp
    # testDl_sc.cpp
    # testDl_msbignum.cpp
    # testDl_cng.cpp
    callback.cpp
    testMontgomery.cpp
    testScsTable.cpp
    testIEEE802_11SaeCustom.cpp
  )

# Need to include an asm file from here.
include_directories(${CMAKE_SOURCE_DIR}/lib)

add_compile_options(-Wno-write-strings)

add_library(symcryptunittest_lib STATIC ${SOURCES})
set_target_properties(symcryptunittest_lib PROPERTIES PREFIX "")