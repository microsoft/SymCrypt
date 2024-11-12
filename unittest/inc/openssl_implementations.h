//
// OpenSSL implementation classes
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <symcrypt.h>
#include <stdint.h>
#include <vector>

class ImpOpenssl {
public:
    static constexpr const char * name = "OpenSSL";
};

VOID
addOpensslAlgs();
