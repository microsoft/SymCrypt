// NuGetTestApplication.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <iomanip>
#include "symcrypt.h"

int main()
{
    std::cout << "SymCrypt NuGet Package Test Application\n";
    std::cout << "=======================================\n\n";

    // Test basic SymCrypt functionality
    BYTE testData[] = "Hello, SymCrypt!";
    BYTE hashResult[SYMCRYPT_SHA256_RESULT_SIZE];

    // Compute SHA-256 hash
    SymCryptSha256(testData, sizeof(testData) - 1, hashResult);

    std::cout << "Input: " << testData << std::endl;
    std::cout << "SHA-256 Hash: ";
    for (int i = 0; i < SYMCRYPT_SHA256_RESULT_SIZE; i++)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hashResult[i];
    }
    std::cout << std::endl;

    std::cout << "\nSymCrypt NuGet package is working correctly!" << std::endl;

    return 0;
}
