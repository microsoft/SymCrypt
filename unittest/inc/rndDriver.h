//
// rndDriver.h Header file for random test driver
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

typedef VOID (* RNDD_TEST_FN)();

VOID
rnddRegisterTestFunction( RNDD_TEST_FN func, _In_ PSTR name, UINT32 weight );

VOID
rnddRegisterInitFunction( RNDD_TEST_FN func );

VOID
rnddRegisterCleanupFunction( RNDD_TEST_FN func );

VOID
rnddRegisterInvariantFunction( RNDD_TEST_FN func );


VOID
rnddRunTest( UINT32 nSeconds, UINT32 nThreads );        

