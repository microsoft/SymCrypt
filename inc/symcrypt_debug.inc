/*
 symcrypt_debug.inc file to synchronize C and Asm information
 Copyright (c) Microsoft Corporation. Licensed under the MIT license.

 This is a file that is included in both C and ASM such that the values are the same on both sides.
 We use the C preprocessor to set ASM constants, as we already need to use the C preprocessor for
 symcryptasm processing (see scripts/symcryptasm_processor.py).
*/

#if defined(DBG)
#define SYMCRYPT_DEBUG 1
#else
#define SYMCRYPT_DEBUG 0
#endif
