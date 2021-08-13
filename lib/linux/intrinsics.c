//
// intrinsics.c
// Replacements for intrinsics not supported by GCC/LLVM
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

void __cpuid(int CPUInfo[4], int InfoType)
{
    asm volatile ("cpuid"
        : "=a" (CPUInfo[0]), "=b" (CPUInfo[1]), "=c" (CPUInfo[2]), "=d" (CPUInfo[3])
        : "a" (InfoType));
}

void __cpuidex(int CPUInfo[4], int InfoType, int ECXValue)
{
    asm volatile ("cpuid"
        : "=a" (CPUInfo[0]), "=b" (CPUInfo[1]), "=c" (CPUInfo[2]), "=d" (CPUInfo[3])
        : "a" (InfoType), "c" (ECXValue));
}