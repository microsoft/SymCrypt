//
// moduletest.cpp
// Test executable for SymCrypt module smoke tests
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <stddef.h>
#include <stdio.h>
#include "symcrypt.h"

int
main( int argc, _In_reads_( argc ) char * argv[] )
{
    SYMCRYPT_MODULE_INIT();
    
    printf("Success!\n");

    return 0;
}

