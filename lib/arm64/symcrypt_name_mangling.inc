// ARM64EC needs to use a modified function name as the code can co-exist with equivalent ARM64 code.
// This macro adds the name mangling only for ARM64EC. This is equivalent to the A64NAME macro in Windows headers

#ifndef _M_ARM64EC
#define ARM64EC_NAME_MANGLE(FuncName) FuncName
#else
#define ARM64EC_NAME_DECORATION_SYMBOL() #
#define ARM64EC_NAME_DECORATE(FuncName) ARM64EC_NAME_DECORATION_SYMBOL() ## FuncName
#define ARM64EC_NAME_MANGLE(FuncName) |ARM64EC_NAME_DECORATE(FuncName)|
#endif
