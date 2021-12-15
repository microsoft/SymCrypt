//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include "precomp.h"

#if 0
#define TEST_CHECK_WOOP( p )    {(p)->checkWoop();}
#define TEST_CHECK_VALUE( p )   {(p)->checkValue();}
#else
#define TEST_CHECK_WOOP( p )
#define TEST_CHECK_VALUE( p )
#endif

#define MAX_INT_DIGITS_STATIC   256

const BYTE PrimeBrainPoolP160[] = {
    0xE9, 0x5E, 0x4A, 0x5F, 0x73, 0x70, 0x59, 0xDC,
    0x60, 0xDF, 0xC7, 0xAD, 0x95, 0xB3, 0xD8, 0x13,
    0x95, 0x15, 0x62, 0x0F,
};

const BYTE PrimeBrainPoolP192[] = {
    0xC3, 0x02, 0xF4, 0x1D, 0x93, 0x2A, 0x36, 0xCD,
    0xA7, 0xA3, 0x46, 0x30, 0x93, 0xD1, 0x8D, 0xB7,
    0x8F, 0xCE, 0x47, 0x6D, 0xE1, 0xA8, 0x62, 0x97,
};

const BYTE PrimeBrainPoolP224[] = {
    0xD7, 0xC1, 0x34, 0xAA, 0x26, 0x43, 0x66, 0x86,
    0x2A, 0x18, 0x30, 0x25, 0x75, 0xD1, 0xD7, 0x87,
    0xB0, 0x9F, 0x07, 0x57, 0x97, 0xDA, 0x89, 0xF5,
    0x7E, 0xC8, 0xC0, 0xFF,
};

const BYTE PrimeBrainPoolP256[] = {
    0xA9, 0xFB, 0x57, 0xDB, 0xA1, 0xEE, 0xA9, 0xBC,
    0x3E, 0x66, 0x0A, 0x90, 0x9D, 0x83, 0x8D, 0x72,
    0x6E, 0x3B, 0xF6, 0x23, 0xD5, 0x26, 0x20, 0x28,
    0x20, 0x13, 0x48, 0x1D, 0x1F, 0x6E, 0x53, 0x77,
};

const BYTE PrimeBrainPoolP320[] = {
    0xD3, 0x5E, 0x47, 0x20, 0x36, 0xBC, 0x4F, 0xB7,
    0xE1, 0x3C, 0x78, 0x5E, 0xD2, 0x01, 0xE0, 0x65,
    0xF9, 0x8F, 0xCF, 0xA6, 0xF6, 0xF4, 0x0D, 0xEF,
    0x4F, 0x92, 0xB9, 0xEC, 0x78, 0x93, 0xEC, 0x28,
    0xFC, 0xD4, 0x12, 0xB1, 0xF1, 0xB3, 0x2E, 0x27,
};

const BYTE PrimeBrainPoolP384[] = {
    0x8C, 0xB9, 0x1E, 0x82, 0xA3, 0x38, 0x6D, 0x28,
    0x0F, 0x5D, 0x6F, 0x7E, 0x50, 0xE6, 0x41, 0xDF,
    0x15, 0x2F, 0x71, 0x09, 0xED, 0x54, 0x56, 0xB4,
    0x12, 0xB1, 0xDA, 0x19, 0x7F, 0xB7, 0x11, 0x23,
    0xAC, 0xD3, 0xA7, 0x29, 0x90, 0x1D, 0x1A, 0x71,
    0x87, 0x47, 0x00, 0x13, 0x31, 0x07, 0xEC, 0x53,
};

const BYTE PrimeBrainPoolP512[] = {
    0xAA, 0xDD, 0x9D, 0xB8, 0xDB, 0xE9, 0xC4, 0x8B,
    0x3F, 0xD4, 0xE6, 0xAE, 0x33, 0xC9, 0xFC, 0x07,
    0xCB, 0x30, 0x8D, 0xB3, 0xB3, 0xC9, 0xD2, 0x0E,
    0xD6, 0x63, 0x9C, 0xCA, 0x70, 0x33, 0x08, 0x71,
    0x7D, 0x4D, 0x9B, 0x00, 0x9B, 0xC6, 0x68, 0x42,
    0xAE, 0xCD, 0xA1, 0x2A, 0xE6, 0xA3, 0x80, 0xE6,
    0x28, 0x81, 0xFF, 0x2F, 0x2D, 0x82, 0xC6, 0x85,
    0x28, 0xAA, 0x60, 0x56, 0x58, 0x3A, 0x48, 0xF3,
};

const BYTE PrimeWapiP192[] = {
    0xBD, 0xB6, 0xF4, 0xFE, 0x3E, 0x8B, 0x1D, 0x9E,
    0x0D, 0xA8, 0xC0, 0xD4, 0x6F, 0x4C, 0x31, 0x8C,
    0xEF, 0xE4, 0xAF, 0xE3, 0xB6, 0xB8, 0x55, 0x1F,
};

const BYTE PrimeNistP192[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

const BYTE PrimeNistP224[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
};

const BYTE PrimeNistP256[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

const BYTE PrimeNistP384[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
};

const BYTE PrimeNistP521[] = {
    0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF,
};

const BYTE PrimeSecP160k[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xFF, 0xFF, 0xAC, 0x73,
};

const BYTE PrimeSecP160r[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x7F, 0xFF, 0xFF, 0xFF,
};

const BYTE PrimeSecP192k[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xEE, 0x37,
};

const BYTE PrimeSecP224r[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xFF, 0xFF, 0xE5, 0x6D,
};

const BYTE PrimeSecP256[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
};

const BYTE PrimeWtlsP160[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFC, 0x80, 0x8F,
};

const BYTE PrimeX962P239[] = {
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

const BYTE PrimeNumsP256[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x43,
};

const BYTE PrimeNumsP384[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xC3,
};

const BYTE PrimeNumsP512[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFD, 0xC7,
};

const BYTE PrimeCurve25519[] = {
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xED,
};

const BYTE Prime1024Rfc5114[] = {
    0xB1, 0x0B, 0x8F, 0x96, 0xA0, 0x80, 0xE0, 0x1D, 0xDE, 0x92, 0xDE, 0x5E, 0xAE, 0x5D, 0x54, 0xEC,
    0x52, 0xC9, 0x9F, 0xBC, 0xFB, 0x06, 0xA3, 0xC6, 0x9A, 0x6A, 0x9D, 0xCA, 0x52, 0xD2, 0x3B, 0x61,
    0x60, 0x73, 0xE2, 0x86, 0x75, 0xA2, 0x3D, 0x18, 0x98, 0x38, 0xEF, 0x1E, 0x2E, 0xE6, 0x52, 0xC0,
    0x13, 0xEC, 0xB4, 0xAE, 0xA9, 0x06, 0x11, 0x23, 0x24, 0x97, 0x5C, 0x3C, 0xD4, 0x9B, 0x83, 0xBF,
    0xAC, 0xCB, 0xDD, 0x7D, 0x90, 0xC4, 0xBD, 0x70, 0x98, 0x48, 0x8E, 0x9C, 0x21, 0x9A, 0x73, 0x72,
    0x4E, 0xFF, 0xD6, 0xFA, 0xE5, 0x64, 0x47, 0x38, 0xFA, 0xA3, 0x1A, 0x4F, 0xF5, 0x5B, 0xCC, 0xC0,
    0xA1, 0x51, 0xAF, 0x5F, 0x0D, 0xC8, 0xB4, 0xBD, 0x45, 0xBF, 0x37, 0xDF, 0x36, 0x5C, 0x1A, 0x65,
    0xE6, 0x8C, 0xFD, 0xA7, 0x6D, 0x4D, 0xA7, 0x08, 0xDF, 0x1F, 0xB2, 0xBC, 0x2E, 0x4A, 0x43, 0x71
};

const BYTE Prime2048Rfc5114[] = {
0xAD, 0x10, 0x7E, 0x1E, 0x91, 0x23, 0xA9, 0xD0, 0xD6, 0x60, 0xFA, 0xA7, 0x95, 0x59, 0xC5, 0x1F,
0xA2, 0x0D, 0x64, 0xE5, 0x68, 0x3B, 0x9F, 0xD1, 0xB5, 0x4B, 0x15, 0x97, 0xB6, 0x1D, 0x0A, 0x75,
0xE6, 0xFA, 0x14, 0x1D, 0xF9, 0x5A, 0x56, 0xDB, 0xAF, 0x9A, 0x3C, 0x40, 0x7B, 0xA1, 0xDF, 0x15,
0xEB, 0x3D, 0x68, 0x8A, 0x30, 0x9C, 0x18, 0x0E, 0x1D, 0xE6, 0xB8, 0x5A, 0x12, 0x74, 0xA0, 0xA6,
0x6D, 0x3F, 0x81, 0x52, 0xAD, 0x6A, 0xC2, 0x12, 0x90, 0x37, 0xC9, 0xED, 0xEF, 0xDA, 0x4D, 0xF8,
0xD9, 0x1E, 0x8F, 0xEF, 0x55, 0xB7, 0x39, 0x4B, 0x7A, 0xD5, 0xB7, 0xD0, 0xB6, 0xC1, 0x22, 0x07,
0xC9, 0xF9, 0x8D, 0x11, 0xED, 0x34, 0xDB, 0xF6, 0xC6, 0xBA, 0x0B, 0x2C, 0x8B, 0xBC, 0x27, 0xBE,
0x6A, 0x00, 0xE0, 0xA0, 0xB9, 0xC4, 0x97, 0x08, 0xB3, 0xBF, 0x8A, 0x31, 0x70, 0x91, 0x88, 0x36,
0x81, 0x28, 0x61, 0x30, 0xBC, 0x89, 0x85, 0xDB, 0x16, 0x02, 0xE7, 0x14, 0x41, 0x5D, 0x93, 0x30,
0x27, 0x82, 0x73, 0xC7, 0xDE, 0x31, 0xEF, 0xDC, 0x73, 0x10, 0xF7, 0x12, 0x1F, 0xD5, 0xA0, 0x74,
0x15, 0x98, 0x7D, 0x9A, 0xDC, 0x0A, 0x48, 0x6D, 0xCD, 0xF9, 0x3A, 0xCC, 0x44, 0x32, 0x83, 0x87,
0x31, 0x5D, 0x75, 0xE1, 0x98, 0xC6, 0x41, 0xA4, 0x80, 0xCD, 0x86, 0xA1, 0xB9, 0xE5, 0x87, 0xE8,
0xBE, 0x60, 0xE6, 0x9C, 0xC9, 0x28, 0xB2, 0xB9, 0xC5, 0x21, 0x72, 0xE4, 0x13, 0x04, 0x2E, 0x9B,
0x23, 0xF1, 0x0B, 0x0E, 0x16, 0xE7, 0x97, 0x63, 0xC9, 0xB5, 0x3D, 0xCF, 0x4B, 0xA8, 0x0A, 0x29,
0xE3, 0xFB, 0x73, 0xC1, 0x6B, 0x8E, 0x75, 0xB9, 0x7E, 0xF3, 0x63, 0xE2, 0xFF, 0xA3, 0x1F, 0x71,
0xCF, 0x9D, 0xE5, 0x38, 0x4E, 0x71, 0xB8, 0x1C, 0x0A, 0xC4, 0xDF, 0xFE, 0x0C, 0x10, 0xE6, 0x4F,
};

const BYTE Prime3072Rfc3526[] = {
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33,
0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64, 0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A,
0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D,
0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B, 0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64,
0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2,
0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31, 0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E,
0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x3A, 0xD2, 0xCA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

typedef struct {
    UINT32  perfCategory;       // used to signal PERF_KEY_ODD, PERF_KEY_PM, or PERF_KEY_NIST
    PCBYTE  pPrime;
    UINT32  nBytes;
} TEST_PRIMES;

#define ADD_NUMBER( n )  &(n)[0], ARRAY_SIZE( n )

const TEST_PRIMES g_testPrimes[]=
{
    {PERF_KEY_PUB_ODD,  ADD_NUMBER( PrimeBrainPoolP160 )},
    {PERF_KEY_PUB_ODD,  ADD_NUMBER( PrimeBrainPoolP192 )},
    {PERF_KEY_PUB_ODD,  ADD_NUMBER( PrimeBrainPoolP224 )},
    {PERF_KEY_PUB_ODD,  ADD_NUMBER( PrimeBrainPoolP256 )},
    {PERF_KEY_PUB_ODD,  ADD_NUMBER( PrimeBrainPoolP320 )},
    {PERF_KEY_PUB_ODD,  ADD_NUMBER( PrimeBrainPoolP384 )},
    {PERF_KEY_PUB_ODD,  ADD_NUMBER( PrimeBrainPoolP512 )},
    {PERF_KEY_PUB_ODD,  ADD_NUMBER( Prime1024Rfc5114 )},
    {PERF_KEY_PUB_ODD,  ADD_NUMBER( Prime2048Rfc5114 )},
    {PERF_KEY_PUB_ODD,  ADD_NUMBER( Prime3072Rfc3526 )},
    {PERF_KEY_PUB_ODD,  ADD_NUMBER( PrimeWapiP192 )},
    {PERF_KEY_PUB_NIST, ADD_NUMBER( PrimeNistP192 )},
    {PERF_KEY_PUB_NIST, ADD_NUMBER( PrimeNistP224 )},
    {PERF_KEY_PUB_NIST, ADD_NUMBER( PrimeNistP256 )},
    {PERF_KEY_PUB_NIST, ADD_NUMBER( PrimeNistP384 )},
    {PERF_KEY_PUB_NIST, ADD_NUMBER( PrimeNistP521 )},
    {PERF_KEY_PUB_ODD,  ADD_NUMBER( PrimeSecP160k )},
    {PERF_KEY_PUB_ODD,  ADD_NUMBER( PrimeSecP160r )},
    {PERF_KEY_PUB_ODD,  ADD_NUMBER( PrimeSecP192k )},
    {PERF_KEY_PUB_ODD,  ADD_NUMBER( PrimeSecP224r )},
    {PERF_KEY_PUB_ODD,  ADD_NUMBER( PrimeSecP256 )},
    {PERF_KEY_PUB_ODD,  ADD_NUMBER( PrimeWtlsP160 )},
    {PERF_KEY_PUB_ODD,  ADD_NUMBER( PrimeX962P239 )},
    {PERF_KEY_PUB_PM,   ADD_NUMBER( PrimeNumsP256 )},
    {PERF_KEY_PUB_PM,   ADD_NUMBER( PrimeNumsP384 )},
    {PERF_KEY_PUB_PM,   ADD_NUMBER( PrimeNumsP512 )},
};

const UINT32 g_nTestPrimes = ARRAY_SIZE( g_testPrimes );

BOOL isPrimePossible( UINT32 nD )
{
    return nD >= SymCryptDigitsFromBits(160) && nD <= SymCryptDigitsFromBits(521);
}

const BYTE CompositeCarmichael1[] = {
    0x02, 0x31,
};

const BYTE CompositeCarmichael2[] = {
    0x04, 0x51,
};

const BYTE CompositeCarmichael3[] = {
    0x06, 0xC1,
};

const BYTE CompositeCarmichael1000[] = {
    0xB7, 0xF7, 0x41, 0x01,
};

const BYTE CompositeCarmichael10000[] = {
    0x01, 0x8E, 0xD9, 0x79, 0x14, 0x91,
};

const BYTE CompositeLargePrimeProduct1[] = {
// 797003437 * 982451653
    0x0A, 0xDD, 0xD6, 0x20, 0x39, 0xAD, 0xEC, 0x21,
};

const BYTE CompositeLargePrimeProduct2[] = {
// 982451579 * 982451581
    0x0D, 0x65, 0x1E, 0x63, 0x50, 0xA6, 0x14, 0x0F,
};

const BYTE CompositeLargePrimeProduct3[] = {
// 982451579 * 982451581 * 982451581
    0x03, 0x10, 0x64, 0xA7, 0xFD, 0xB7, 0x74, 0x62, 0x39, 0xDD, 0x16, 0x53,
};

typedef struct {
    PCBYTE  pComposite;
    UINT32  nBytes;
} TEST_COMPOSITES;

const TEST_COMPOSITES g_testComposites[]=
{
    {ADD_NUMBER( CompositeCarmichael1 )},
    {ADD_NUMBER( CompositeCarmichael2 )},
    {ADD_NUMBER( CompositeCarmichael3 )},
    {ADD_NUMBER( CompositeCarmichael1000 )},
    {ADD_NUMBER( CompositeCarmichael10000 )},
    {ADD_NUMBER( CompositeLargePrimeProduct1 )},
    {ADD_NUMBER( CompositeLargePrimeProduct2 )},
    {ADD_NUMBER( CompositeLargePrimeProduct3 )},
};

const UINT32 g_nTestComposites = ARRAY_SIZE( g_testComposites );

BOOL isCompositePossible( UINT32 nD )
{
    return nD >= SymCryptDigitsFromBits(10) && nD <= SymCryptDigitsFromBits(41);
}

PCBYTE
getPerfTestModulus( UINT32 exKeySize )
{
    UINT32 keyBytes = exKeySize & 0x00ffffff;
    UINT32 keyFlags = exKeySize & 0xff000000;

    keyFlags &= ~PERF_KEY_PRIME;        // ignore this flag

    if( keyFlags == PERF_KEY_SECRET || keyFlags == PERF_KEY_PUBLIC )
    {
        keyFlags = PERF_KEY_PUB_ODD;
    }

    for( int i=0; i< ARRAY_SIZE( g_testPrimes ); i++ )
    {
        if( g_testPrimes[i].perfCategory == keyFlags && g_testPrimes[i].nBytes == keyBytes )
        {
            return g_testPrimes[i].pPrime;
        }
    }
    CHECK3( FALSE, "Did not find suitable test modulus %08x", exKeySize );
    return NULL;
}

class ArithInt {
public:
    ArithInt( SIZE_T nDigits );
    virtual ~ArithInt();

private:
    ArithInt( ArithInt const & );
    VOID operator =(  ArithInt const & );


public:
    VOID checkWoop();
    UINT32 computeWoop();
    VOID setRandom();

    PSYMCRYPT_INT   m_pScInt;
    UINT32          m_woop;
    UINT32          m_nDigits;
    PBYTE           m_pAllocated;
    SIZE_T          m_cbAllocated;

    static LONGLONG    m_nArithIntObjects;
};

class ArithDivisor {
public:
    ArithDivisor( SIZE_T nDigits, UINT32 nFail = 0 );
    virtual ~ArithDivisor();

private:
    ArithDivisor( ArithDivisor const & );
    VOID operator =(  ArithDivisor const & );


public:
    PSYMCRYPT_DIVISOR   m_pScDivisor;
    UINT32              m_woop;
    UINT32              m_nDigits;
    PBYTE               m_pAllocated;
    SIZE_T              m_cbAllocated;

    static LONGLONG    m_nArithDivisorObjects;
};

class ArithModulus;

class ArithModElement {
public:
    ArithModElement( ArithModulus * pModulus, UINT32 nFail = 0 );
    virtual ~ArithModElement();

    VOID checkValue();          // checks the invariant that the modelement == int

private:
    ArithModElement( ArithModElement const & );
    VOID operator =(  ArithModElement const & );

public:
    ArithModulus *          m_pModulus;
    PSYMCRYPT_MODELEMENT    m_pScModElement;

    PBYTE                   m_pAllocated;
    SIZE_T                  m_cbAllocated;

    PSYMCRYPT_INT           m_pScInt;           // The value that this modelement is supposed to have. size: nDigits
    PSYMCRYPT_INT           m_pScTmp1;          // Tmp location, size of modulus
    PSYMCRYPT_INT           m_pScTmp2;          // Tmp location, 2x size of modulus

    static INT64            m_nArithModElementObjects;
};

class ArithModulus {
public:
    ArithModulus( SIZE_T nDigits, UINT32 nFail = 0 );
    virtual ~ArithModulus();

private:
    ArithModulus( ArithModulus const & );
    VOID operator =(  ArithModulus const & );

public:
    PSYMCRYPT_MODULUS   m_pScModulus;
    UINT32              m_flags;
    UINT32              m_nDigits;
    PBYTE               m_pAllocated;
    SIZE_T              m_cbAllocated;

    PSYMCRYPT_INT       m_pScInt;       // Integer value of modulus, used for validating computations
    PSYMCRYPT_DIVISOR   m_pScDivisor;   // used for validating modular computations

    std::vector<ArithModElement *> m_elVector;      // set of ModElements for this modulus
    static INT64        m_nArithModulusObjects;
};

INT64 ArithModulus::m_nArithModulusObjects = 0;
INT64 ArithModElement::m_nArithModElementObjects = 0;

UINT32 g_woopMod;

UINT32 g_bitsPerDigit;          // # bits per digit, derived during test
UINT32 g_bytesPerDigit;         // # bytes per digit, derived during test

UINT32 g_digitLimit;            // max # digits that we will use, computed from MAX_INT_BITS

std::vector<ArithInt *> g_intObjectVector[MAX_INT_DIGITS_STATIC + 1];       // Set of Int objects to operate on
SIZE_T  g_nIntPerVectorTarget;  // desired # INT objects for each digit size

std::vector<ArithDivisor *> g_divisorObjectVector[MAX_INT_DIGITS_STATIC + 1];   // set of Divisor objects to operate on
SIZE_T  g_nDivisorPerVectorTarget;

std::vector<ArithModulus *> g_modulusObjectVector[MAX_INT_DIGITS_STATIC + 1];   // Set of Modulus objects.
SIZE_T  g_nModulusPerVectorTarget;

SIZE_T g_nModElementPerVectorTarget;

UINT32 g_carryWoop[MAX_INT_DIGITS_STATIC + 1];          // woop representation of the carry bit that comes out of an n-digit addition

SYMCRYPT_ASYM_ALIGN BYTE g_scratch[1 << 22];        // General scrach space used by all functions. Large enough for any test.


UINT32
bitSizeOfUint32( UINT32 v )
{
    UINT32 res = 0;
    while( v != 0 )
    {
        v >>= 1;
        res += 1;
    }
    return res;
}


INT64 ArithInt::m_nArithIntObjects = 0;
INT64 ArithDivisor::m_nArithDivisorObjects = 0;

ArithInt::ArithInt( SIZE_T nDigits )
{
    SIZE_T nBytes;
    UINT32 nBits;

    m_nDigits = (UINT32) nDigits;
    CHECK( m_nDigits == nDigits, "?" );

    if( (g_rng.byte() & 1) == 0 )
    {
        // Use the SymCrypt allocator
        m_pAllocated = NULL;
        m_pScInt = SymCryptIntAllocate( (UINT32) nDigits );
        CHECK( m_pScInt != NULL, "Error during INT allocation" );
    } else {
        // Use our own memory buffer, and add magics around it to detect overruns.

        nBytes = SymCryptSizeofIntFromDigits( (UINT32) nDigits );

        nBits = 0;
        while( SymCryptDigitsFromBits( nBits + 1 ) <= nDigits )
        {
            nBits++;
        }
        CHECK3( nBytes <= SYMCRYPT_SIZEOF_INT_FROM_BITS( nBits ), "Size mismatch %d", nBits );

        m_pAllocated = (PBYTE) AllocWithChecksSc( nBytes );
        m_cbAllocated = nBytes;

        //
        // Set to zero so that we can test the SymcryptWipe later
        //
        SymCryptWipe( m_pAllocated, nBytes );

        m_pScInt = SymCryptIntCreate( (PBYTE) m_pAllocated, nBytes, (UINT32) nDigits );
        CHECK( m_pScInt != NULL, "Error during INT creation" );
    }

    setRandom();

    checkWoop();

    InterlockedIncrement64( &m_nArithIntObjects );
}

ArithInt::~ArithInt()
{
    InterlockedDecrement64( &m_nArithIntObjects );

    checkWoop();
    if( m_pAllocated == NULL )
    {
        SymCryptIntFree( m_pScInt );
        m_pScInt = NULL;
    } else {
        SymCryptIntWipe( m_pScInt );
        m_pScInt = NULL;

        BYTE b = 0;
        for( SIZE_T i=0; i<m_cbAllocated; i++ )
        {
            b |= m_pAllocated[i];
        }
        CHECK( b == 0, "SymCryptWipe did not wipe everything" );

        FreeWithChecksSc( m_pAllocated );
        m_pAllocated = NULL;
    }
}

VOID
ArithInt::setRandom()
{
    BYTE                    buf[MAX_INT_BYTES];
    SIZE_T                  i;
    SIZE_T                  j;
    SYMCRYPT_NUMBER_FORMAT  format;
    BOOL                    success;
    UINT64                  woop;
    SIZE_T                  nBytes;
    BYTE                    rand;
    BYTE                    b;
    do {
        //
        // First we construct the input buffer.
        // Most of the time we use one that will fit, sometimes we make it too big.
        // To generate corner cases, the numbers we generate are random, low-Hamming weight,
        // somtimes inverted (for high Hamming weight)
        //
        rand = g_rng.byte();

        if( (rand & 0xe0) == 0 )
        {
            nBytes = g_rng.sizet( MAX_INT_BYTES );  // random up to the max
        } else {
            nBytes = (m_nDigits * g_bitsPerDigit + 7)/ 8;    // Exact size needed
        }
        CHECK( nBytes <= sizeof( buf ), "?" );

        if( (rand & 1) == 0 )
        {
            // random value
            for( i=0; i<nBytes; i++ )
            {
                buf[i] = g_rng.byte();
            }
        } else {
            // Low Hamming-weight
            if( nBytes > 0 )
            {
                SymCryptWipe( buf, nBytes );
                while( g_rng.byte() >= 16 )  // Average weight = 16
                {
                    SIZE_T bit = g_rng.sizet( 8 * nBytes );
                    buf[ bit / 8] |= 1 << (bit % 8);
                }
            }
        }

        if( (rand & 2) == 0 )
        {
            // invert the buffer; this produces high-Hamming weight numbers
            for( i=0; i<nBytes; i++ )
            {
                buf[i] ^= 0xff;
            }
        }

        //
        // Predict whether the number will fit. Note that nBytes == 0 is valid.
        //
        i = 0;
        b = 0;
        while( i < nBytes )
        {
            b = buf[i];
            i += 1;
            if( b != 0 )
            {
                break;
            }
        }
        SIZE_T nBits = 8*(nBytes - i ) + bitSizeOfUint32( b );
        success = nBits <= m_nDigits * g_bitsPerDigit;

        // Compute the woop value, assuming MSB first
        woop = 0;
        for( i=0; i<nBytes; i++ )
        {
            woop = ((woop<<8) + buf[i]) % g_woopMod;
        }

        if( (rand & 4) == 0 )
        {
            format = SYMCRYPT_NUMBER_FORMAT_LSB_FIRST;
            i = 0;
            j = nBytes == 0 ? 0 : nBytes - 1;
            while( i < j )
            {
                BYTE t = buf[i];
                buf[i] = buf[j];
                buf[j] = t;
                i += 1;
                j -= 1;
            }
        } else {
            format = SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
        }

        SYMCRYPT_ERROR scError;
        scError = SymCryptIntSetValue( buf, nBytes, format, m_pScInt );
        if( scError == SYMCRYPT_NO_ERROR )
        {
            CHECK( success, "Unexpected success in SetValue" );
        } else {
            CHECK( !success, "Unexpected failure in SetValue" );
        }
    } while( !success );    // Try again if failure; we have to set a value to get a consistent state

    m_woop = (UINT32)woop;

    // checkWoop();
}

C_ASSERT( (MAX_INT_BYTES & 3 ) == 0 );

UINT32
ArithInt::computeWoop()
{
    BYTE buf[MAX_INT_BYTES];
    SYMCRYPT_ERROR scError;

    scError = SymCryptIntGetValue( m_pScInt, buf, sizeof( buf ), SYMCRYPT_NUMBER_FORMAT_LSB_FIRST );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    UINT64 w = 0;
    for( int i= MAX_INT_BYTES/4 - 1; i >= 0; i-- )
    {
        w = (w << 32) | *(UINT32*)( &buf[4*i] );
        w = w % g_woopMod;
    }

    return (UINT32) w;
}

VOID
ArithInt::checkWoop()
{
    CHECK( m_woop == computeWoop(), "Woop value mismatch %" );
}

VOID
testDigitsFromBits()
{
    UINT32 nDigits, bitsPerDigit, nBits, n;

    nDigits = 0;
    bitsPerDigit = 0;
    nBits = 0;
    while( nBits < MAX_INT_BITS || bitsPerDigit == 0 )      // Make sure we compute bits-per-digit even when we test only small numbers
    {
        nBits += 1;
        n = SymCryptDigitsFromBits( nBits );
        CHECK( n == nDigits || n == nDigits + 1, "?" );
        if( bitsPerDigit == 0 && n > 1 )
        {
            bitsPerDigit = nBits - 1;
        }
        if( bitsPerDigit > 0 )
        {
            CHECK( n == (nBits + bitsPerDigit - 1) / bitsPerDigit, "Wrong # digits?" );
        }
        nDigits = n;
    }

    CHECK( bitsPerDigit > 0, "?" );
    g_bitsPerDigit = bitsPerDigit;
    CHECK( bitsPerDigit % 8 == 0, "Test code currently assumes that bytesPerDigit is an integer" );
    g_bytesPerDigit = bitsPerDigit / 8;
}

VOID
setupCarryWoops()
{
    UINT32 w = 2 % g_woopMod;
    SIZE_T  bits = 1;

    // invariant: w = 2^bits % g_woopMod

    for( SIZE_T i=1; i<g_digitLimit; i++ )
    {
        while( bits < i * g_bitsPerDigit )
        {
            w = ((UINT64) w * 2) % g_woopMod;
            bits += 1;
        }
        g_carryWoop[i] = w;
    }
}

VOID
initIntObjects()
{
    g_nIntPerVectorTarget = 100;
    CHECK( g_digitLimit <= MAX_INT_DIGITS_STATIC + 1, "?" );
}

VOID
cleanupIntObjects()
{
    for( UINT32 i=1; i < g_digitLimit; i++ )
    {
        while( !g_intObjectVector[i].empty() )
        {
            delete g_intObjectVector[i].back();
            g_intObjectVector[i].pop_back();
        }
    }

    CHECK( ArithInt::m_nArithIntObjects == 0, "Not all int objects deleted" );
}

ArithInt *
randomArithInt( SIZE_T nD, UINT32 nFail = 0 )
//
// Returns a random ArithInt. nFails is a parameter that the caller can pass to indicate how often
// the result was unsatisfactorilly according to the caller's criteria. If nFails gets big enough,
// this function will start returning fresh random Ints which should satisfy the criteria eventually.
//
{
    ArithInt * res = NULL;
    SIZE_T n;

    CHECK( nD < g_digitLimit, "too many digits" );
    n = g_intObjectVector[nD].size();

    if( n == 0 || nFail > 10 )
    {
        // Add an item
        res = new ArithInt( nD );
        g_intObjectVector[nD].push_back( res );
        dprint( "[created Int(%d)]", (int)nD );
    } else {
        res = g_intObjectVector[nD][g_rng.sizet(n)];
    }

    return res;
}

VOID
checkAllIntWoops()
{
    dprint( "-" );
    for( SIZE_T nD = 1; nD < g_digitLimit; nD++ )
    {
        SIZE_T n = g_intObjectVector[nD].size();
        for( SIZE_T i=0; i<n; i++ )
        {
            g_intObjectVector[nD][i]->checkWoop();
        }
    }
    dprint( "+" );
}

VOID
testIntObjectLifetime()
{
    SIZE_T  nD = g_rng.sizet( 1, g_digitLimit );
    SIZE_T  n = g_intObjectVector[nD].size();

    // decide if we will add or remove an object
    SIZE_T  r = g_rng.sizet( 2 * g_nIntPerVectorTarget );

    if( r < n )
    {
        // Remove an item
        SIZE_T index = g_rng.sizet(n);
        ArithInt * p = g_intObjectVector[nD][index];
        g_intObjectVector[nD].erase( g_intObjectVector[nD].begin() + index );
        delete p;
        dprint( "Int[%d]=%d remove, ", (int) nD, (int) n );
    } else {
        // Add an item
        g_intObjectVector[nD].push_back( new ArithInt( nD ) );
        dprint( "Int[%d]=%d add, ", (int) nD, (int) n );
    }
}

VOID
testIntCopy()
{
    SIZE_T nD = g_rng.sizet( 1, g_digitLimit );

    ArithInt *pSrc = randomArithInt( nD );
    ArithInt *pDst  = randomArithInt( nD );

    pDst->checkWoop();

    SymCryptIntCopy( pSrc->m_pScInt, pDst->m_pScInt );
    pDst->m_woop = pSrc->m_woop;

    TEST_CHECK_WOOP( pDst );
}

VOID
testIntBitsizeOfValue()
{
    BYTE            buf[MAX_INT_BYTES];
    SYMCRYPT_ERROR  scError;

    SIZE_T nD = g_rng.sizet( 1, g_digitLimit );
    ArithInt *pSrc = randomArithInt( nD );

    scError = SymCryptIntGetValue( pSrc->m_pScInt, buf, sizeof( buf ), SYMCRYPT_NUMBER_FORMAT_LSB_FIRST );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    UINT32 i = MAX_INT_BYTES - 1;
    while( i > 0 && buf[i] == 0 )
    {
        i--;
    }

    UINT32 expectedResult = 8*i + bitSizeOfUint32( buf[i] );

    CHECK( expectedResult == SymCryptIntBitsizeOfValue( pSrc->m_pScInt ), "Wrong bitsize reported" );
}


VOID
testIntCopyMixedSize()
{
    SYMCRYPT_ERROR scError;
    SIZE_T nD1 = g_rng.sizet( 1, g_digitLimit );
    SIZE_T nD2 = g_rng.sizet( 1, g_digitLimit );

    ArithInt *pSrc = randomArithInt( nD1 );
    ArithInt *pDst  = randomArithInt( nD2 );

    UINT32 srcBitSize = SymCryptIntBitsizeOfValue( pSrc->m_pScInt );

    pDst->checkWoop();

    scError = SymCryptIntCopyMixedSize( pSrc->m_pScInt, pDst->m_pScInt );

    if( scError != SYMCRYPT_NO_ERROR )
    {
        CHECK( srcBitSize >= nD2 * g_bitsPerDigit, "CopyMixedSize failed when it shouldn't" );
        pDst->setRandom();
    } else {
        // no error
        CHECK( srcBitSize <= nD2 * g_bitsPerDigit, "CopyMixedSize succeeded when it shouldn't" );
        pDst->m_woop = pSrc->m_woop;
    }

    TEST_CHECK_WOOP( pDst );
}

VOID
testIntSetValue()
{
    SIZE_T                  nD = g_rng.sizet( 1, g_digitLimit );

    ArithInt *pDst = randomArithInt( nD );
    pDst->checkWoop();
    pDst->setRandom();

    TEST_CHECK_WOOP( pDst );
}

VOID
testIntSetValueUint32()
{
    SIZE_T                  nD = g_rng.sizet( 1, g_digitLimit );
    UINT32                  v;

    ArithInt *pDst = randomArithInt( nD );
    v = g_rng.uint32();
    v = v >> ((g_rng.byte() & 0x03)*8);               // Zero out 0, 1, 2, or 3 bytes

    pDst->checkWoop();
    SymCryptIntSetValueUint32( v, pDst->m_pScInt );
    pDst->m_woop = v % g_woopMod;

    TEST_CHECK_WOOP( pDst );
}

VOID
testIntGetValue()
{
    BYTE                    buf[MAX_INT_BYTES];
    SIZE_T                  nD = g_rng.sizet(1, g_digitLimit );
    PBYTE                   pB;
    INT32                   step;
    SYMCRYPT_NUMBER_FORMAT  format;
    SYMCRYPT_ERROR          scError;
    UINT64                  woop;
    UINT32                  i;
    SIZE_T                  nBytes;
    BYTE                    rand;
    BOOLEAN                 success;

    ArithInt *pSrc = randomArithInt( nD );

    rand = g_rng.byte();
    if( (rand & 0xc0) == 0 )
    {
        nBytes = g_rng.sizet( MAX_INT_BYTES );  // random up to the max, 1/4 of the time
    } else {
        nBytes = (pSrc->m_nDigits * g_bitsPerDigit + 7)/ 8 ;      // Minimum normally required
        nBytes += g_rng.sizet( MAX_INT_BYTES - nBytes + 1 );    // random up to the maximum
    }
    CHECK( nBytes <= sizeof( buf ), "?" );

    if( (rand & 1) == 0 )
    {
        format = SYMCRYPT_NUMBER_FORMAT_LSB_FIRST;
        pB = buf + nBytes - 1;
        step = -1;
    } else {
        format = SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
        pB = buf;
        step = 1;
    }

    success = SymCryptIntBitsizeOfValue( pSrc->m_pScInt ) <= 8 * nBytes;
    scError = SymCryptIntGetValue( pSrc->m_pScInt, buf, nBytes, format );

    if( scError == SYMCRYPT_NO_ERROR )
    {
        CHECK( success, "Unexpected success in IntGetValue" );
    } else {
        CHECK( !success, "Unexpected failure in IntGetValue" );
        goto cleanup;
    }

    // Compute the woop value, assuming MSB first
    woop = 0;
    for( i=0; i<nBytes; i++ )
    {
        woop = ((woop<<8) + *pB) % g_woopMod;
        pB += step;
    }

    CHECK( woop == pSrc->m_woop, "Woop mismatch" );

cleanup:
    ;
}

VOID
testIntGetValueLsbits()
{
    BYTE                    buf[MAX_INT_BYTES];
    SIZE_T                  nD = g_rng.sizet(1, g_digitLimit );
    SYMCRYPT_ERROR          scError;
    UINT32                  v;
    UINT64                  v64;

    ArithInt *pSrc = randomArithInt( nD );

    v = SymCryptIntGetValueLsbits32( pSrc->m_pScInt );
    v64 = SymCryptIntGetValueLsbits64( pSrc->m_pScInt );

    scError = SymCryptIntGetValue( pSrc->m_pScInt, buf, sizeof(buf), SYMCRYPT_NUMBER_FORMAT_LSB_FIRST );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    CHECK( v == SYMCRYPT_LOAD_LSBFIRST32( buf ), "IntGetValueLsb32 mismatch" );
    CHECK( v64 == SYMCRYPT_LOAD_LSBFIRST64( buf ), "IntGetValueLsb64 mismatch" );
}

VOID
testIntAddUint32()
{
    SIZE_T      nD = g_rng.sizet(1, g_digitLimit );
    ArithInt    *pSrc = randomArithInt( nD );
    ArithInt    *pDst = randomArithInt( nD );
    UINT32      v;
    UINT32      carry;

    v = g_rng.uint32();

    pDst->checkWoop();
    carry = SymCryptIntAddUint32( pSrc->m_pScInt, v, pDst->m_pScInt );
    pDst->m_woop = ((UINT64)pSrc->m_woop + (v % g_woopMod) + g_woopMod - carry * g_carryWoop[nD]) % g_woopMod;

    TEST_CHECK_WOOP( pDst );
}

VOID
testIntAddSameSize()
{
    SIZE_T      nD = g_rng.sizet(1, g_digitLimit );
    ArithInt    *pSrc1 = randomArithInt( nD );
    ArithInt    *pSrc2 = randomArithInt( nD );
    ArithInt    *pDst  = randomArithInt( nD );
    UINT32      carry;

    pDst->checkWoop();
    carry = SymCryptIntAddSameSize( pSrc1->m_pScInt, pSrc2->m_pScInt, pDst->m_pScInt );
    pDst->m_woop = ((UINT64)pSrc1->m_woop + pSrc2->m_woop + g_woopMod - carry * g_carryWoop[nD]) % g_woopMod;

    TEST_CHECK_WOOP( pDst );
}

VOID
testIntAddMixedSize()
{
    SIZE_T      nD1  = g_rng.sizet(1, g_digitLimit );
    SIZE_T      nD2  = g_rng.sizet(1, g_digitLimit );
    SIZE_T      nDdst;
    UINT32      carry;
    BYTE        rand;

    rand = g_rng.byte();

    nDdst = SYMCRYPT_MAX( nD1, nD2 );
    if( (rand & 1) == 0 )
    {
        nDdst += g_rng.sizet( g_digitLimit - nDdst );
    }

    ArithInt    *pSrc1 = randomArithInt( nD1 );
    ArithInt    *pSrc2 = randomArithInt( nD2 );
    ArithInt    *pDst  = randomArithInt( nDdst );

    pDst->checkWoop();
    carry = SymCryptIntAddMixedSize( pSrc1->m_pScInt, pSrc2->m_pScInt, pDst->m_pScInt );
    pDst->m_woop = ((UINT64)pSrc1->m_woop + pSrc2->m_woop + g_woopMod - carry * g_carryWoop[nDdst]) % g_woopMod;

    TEST_CHECK_WOOP( pDst );
}


VOID
testIntSubUint32()
{
    SIZE_T      nD = g_rng.sizet(1, g_digitLimit );
    ArithInt    *pSrc = randomArithInt( nD );
    ArithInt    *pDst = randomArithInt( nD );
    UINT32      v;
    UINT32      carry;

    v = g_rng.uint32();

    pDst->checkWoop();
    carry = SymCryptIntSubUint32( pSrc->m_pScInt, v, pDst->m_pScInt );
    pDst->m_woop = ((UINT64)pSrc->m_woop + g_woopMod - (v % g_woopMod) + carry * g_carryWoop[nD]) % g_woopMod;

    TEST_CHECK_WOOP( pDst );
}

VOID
testIntSubSameSize()
{
    SIZE_T      nD = g_rng.sizet(1, g_digitLimit );
    ArithInt    *pSrc1 = randomArithInt( nD );
    ArithInt    *pSrc2 = randomArithInt( nD );
    ArithInt    *pDst  = randomArithInt( nD );
    UINT32      carry;

    dprint( "nD=%d,", (int)nD );

    pDst->checkWoop();
    //pSrc1->checkWoop();
    //pSrc2->checkWoop();
    carry = SymCryptIntSubSameSize( pSrc1->m_pScInt, pSrc2->m_pScInt, pDst->m_pScInt );
    pDst->m_woop = ((UINT64)pSrc1->m_woop + g_woopMod - pSrc2->m_woop + carry * g_carryWoop[nD]) % g_woopMod;

    TEST_CHECK_WOOP( pDst );
}

VOID
testIntSubMixedSize()
{
    SIZE_T      nD1  = g_rng.sizet(1, g_digitLimit );
    SIZE_T      nD2  = g_rng.sizet(1, g_digitLimit );
    SIZE_T      nDdst;
    UINT32      carry;
    BYTE        rand;

    rand = g_rng.byte();

    nDdst = SYMCRYPT_MAX( nD1, nD2 );
    if( (rand & 1) == 0 )
    {
        nDdst += g_rng.sizet( g_digitLimit - nDdst );
    }

    ArithInt    *pSrc1 = randomArithInt( nD1 );
    ArithInt    *pSrc2 = randomArithInt( nD2 );
    ArithInt    *pDst  = randomArithInt( nDdst );

    pDst->checkWoop();
    carry = SymCryptIntSubMixedSize( pSrc1->m_pScInt, pSrc2->m_pScInt, pDst->m_pScInt );
    pDst->m_woop = ((UINT64)pSrc1->m_woop + g_woopMod - pSrc2->m_woop + carry * g_carryWoop[nDdst]) % g_woopMod;

    TEST_CHECK_WOOP( pDst );
}

VOID
testIntNeg()
{
    SIZE_T      nD = g_rng.sizet(1, g_digitLimit );
    ArithInt    *pSrc = randomArithInt( nD );
    ArithInt    *pDst = randomArithInt( nD );
    UINT32      mask;

    pDst->checkWoop();

    // if Src == 0, the answer is still zero and not Dst.capacity.
    mask = SymCryptIntIsEqualUint32( pSrc->m_pScInt, 0 );

    SymCryptIntNeg( pSrc->m_pScInt, pDst->m_pScInt );

    pDst->m_woop = ((UINT64) g_woopMod - pSrc->m_woop + (~mask & g_carryWoop[nD]) ) % g_woopMod;

    TEST_CHECK_WOOP( pDst );
}

VOID
testIntGetBits()
{
    BYTE                    buf[MAX_INT_BYTES] = { 0 };
    SIZE_T                  nD = g_rng.sizet(1, g_digitLimit );
    SYMCRYPT_ERROR          scError;

    UINT32                  iBit = 0;
    UINT32                  nBits = 0;

    UINT64                  received = 0;
    UINT64                  desired = 0;

    ArithInt *pSrc = randomArithInt( nD );

    // Pick a random bit position
    iBit = (UINT32)g_rng.sizet(0, SymCryptIntBitsizeOfObject( pSrc->m_pScInt ));

    // Pick a random number of desired bits (up to 32 or the MSB of the object)
    do
    {
        nBits = (UINT32)g_rng.sizet(1, 33);
    }
    while (iBit + nBits > SymCryptIntBitsizeOfObject( pSrc->m_pScInt )) ;

    // Main function to test
    received = SymCryptIntGetBits( pSrc->m_pScInt, iBit, nBits );

    // Verify the result via SymCryptIntGetValue
    scError = SymCryptIntGetValue( pSrc->m_pScInt, buf, sizeof(buf), SYMCRYPT_NUMBER_FORMAT_LSB_FIRST );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    // Fill the desired with as many bytes possibly needed
    for (UINT32 i=0; i<sizeof(UINT64); i++)
    {
        if (iBit/8 + i < MAX_INT_BYTES)
        {
            desired |= ((UINT64)buf[iBit/8 + i]) << (i*8);
        }
    }

    // Shift right appropriately
    desired >>= (iBit%8);

    // Mask (shifting UINT64 works with nBits==32 and nBits==0)
    desired &= (((UINT64) 1 << nBits) - 1);

    // Check that the result is correct
    CHECK( received == desired, "IntGetBits mismatch" );
}

VOID
testIntSetBits()
{
    BYTE                    bufBefore[MAX_INT_BYTES] = { 0 };
    BYTE                    bufAfter[MAX_INT_BYTES] = { 0 };

    SIZE_T                  nD = g_rng.sizet(1, g_digitLimit );
    SYMCRYPT_ERROR          scError;

    UINT32                  iBit = 0;
    UINT32                  nBits = 0;

    UINT64                  value = 0;
    UINT64                  mask = 0;

    ArithInt *pDst = randomArithInt( nD );

    // Pick a random UINT32 value
    value = g_rng.uint32();

    // Pick a random bit position
    iBit = (UINT32)g_rng.sizet(0, SymCryptIntBitsizeOfObject( pDst->m_pScInt ));

    // Pick a random number of desired bits (up to 32 or the MSB of the object)
    do
    {
        nBits = (UINT32)g_rng.sizet(1, 33);
    }
    while (iBit + nBits > SymCryptIntBitsizeOfObject( pDst->m_pScInt )) ;

    // Get the original value
    scError = SymCryptIntGetValue( pDst->m_pScInt, bufBefore, sizeof(bufBefore), SYMCRYPT_NUMBER_FORMAT_LSB_FIRST );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    // Main function to test - Set the new bits
    SymCryptIntSetBits( pDst->m_pScInt, (UINT32)value, iBit, nBits );

    // Verify the result via SymCryptIntGetValue
    scError = SymCryptIntGetValue( pDst->m_pScInt, bufAfter, sizeof(bufAfter), SYMCRYPT_NUMBER_FORMAT_LSB_FIRST );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    // Mask the value and align both with the bytes
    mask = ((UINT64)1<<nBits) - 1;
    value &= mask;
    value <<= (iBit%8);
    mask <<= (iBit%8);

    // Loop through all bytes
    for (UINT32 i=0; i<MAX_INT_BYTES; i++)
    {
        if ( (i>= iBit/8) && (i<= (iBit+nBits-1)/8) )
        {
            CHECK( ( (bufBefore[i] & ~((BYTE)mask)) | ((BYTE)value & (BYTE)mask) ) == bufAfter[i], "IntSetBits mismatch");

            mask >>= 8;
            value >>= 8;
        }
        else
        {
            CHECK( bufBefore[i] == bufAfter[i], "IntSetBits mismatch");
        }
    }

    // Compute the new woop
    pDst->m_woop = pDst->computeWoop();

    TEST_CHECK_WOOP( pDst );
}

VOID
testIntMulPow2()
{
    BYTE        bufSrc[MAX_INT_BYTES + 1];
    BYTE        bufDst[MAX_INT_BYTES];

    SIZE_T      nD = g_rng.sizet(1, g_digitLimit );
    SIZE_T      nBytes = nD * g_bytesPerDigit;


    ArithInt    *pSrc = randomArithInt( nD );
    ArithInt    *pDst = randomArithInt( nD );

    pDst->checkWoop();

    SIZE_T exp = g_rng.sizet( (nD+2) * g_bitsPerDigit );

    SymCryptIntGetValue( pSrc->m_pScInt, bufSrc, nBytes, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST );
    bufSrc[nBytes] = 0;

    SymCryptIntMulPow2( pSrc->m_pScInt, exp, pDst->m_pScInt );

    SymCryptIntGetValue( pDst->m_pScInt, bufDst, nBytes, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST );

    SIZE_T expBytes = exp/8;
    SIZE_T expBits = exp % 8;

    UINT64 w = 0;
    for( SIZE_T i=0; i<nBytes; i++ )
    {
        w = ((w << 8) + bufDst[i]) % g_woopMod;
        if( i + expBytes >= nBytes )
        {
            CHECK( bufDst[i] == 0, "Unexpected nonzero byte in MulPow2 result" );
        } else {
            UINT32 t = (bufSrc[i + expBytes] << 8) +  bufSrc[i + expBytes + 1];
            CHECK( bufDst[i] == ((t >> (8 - expBits) ) & 0xff), "Unexpected result in MulPow2" );
        }
    }

    pDst->m_woop = (UINT32) w;

    TEST_CHECK_WOOP( pDst );
}

VOID
testIntModPow2()
{
    BYTE    bufSrc[ MAX_INT_BYTES ];

    SIZE_T      nD = g_rng.sizet(1, g_digitLimit );
    SIZE_T      nBytes = nD * g_bytesPerDigit;
    UINT32      w;


    ArithInt    *pSrc = randomArithInt( nD );
    ArithInt    *pDst = randomArithInt( nD );

    pDst->checkWoop();

    SIZE_T exp = g_rng.sizet( (nD+2) * g_bitsPerDigit );

    SymCryptIntGetValue( pSrc->m_pScInt, bufSrc, nBytes, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST );

    SymCryptIntModPow2( pSrc->m_pScInt, exp, pDst->m_pScInt );

    if( exp == 0 )
    {
        w = 0;
    }
    else if( exp >= nD * g_bitsPerDigit )
    {
        w = pSrc->m_woop;
    } else
    {
        SIZE_T i = exp / 8;
        w = bufSrc[i] & ((UINT32)0xff >> (8 - (exp % 8)));
        while( i > 0 )
        {
            i--;
            w = (((UINT64)w << 8) + bufSrc[i] )% g_woopMod;
        }
    }
    pDst->m_woop = w;

    TEST_CHECK_WOOP( pDst );
}


VOID
testIsEqualUint32()
{
    BYTE            buf[MAX_INT_BYTES];
    SIZE_T          nD = g_rng.sizet(1, g_digitLimit );
    SIZE_T          nBytes = nD * g_bytesPerDigit;
    UINT32          mask;
    UINT32          expected;
    SYMCRYPT_ERROR  scError;

    ArithInt    *pSrc = randomArithInt( nD );

    scError = SymCryptIntGetValue( pSrc->m_pScInt, buf, nBytes, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    UINT32 v = SYMCRYPT_LOAD_LSBFIRST32( buf );

    BYTE b = 0;
    for( UINT32 i = 4; i < nBytes; i++ )
    {
        b |= buf[i];
    }
    expected = b == 0 ? (UINT32)-1 : 0;

    mask = SymCryptIntIsEqualUint32( pSrc->m_pScInt, v );
    CHECK( mask == expected, "Equality result not correct" );
    CHECK( SymCryptIntIsEqualUint32( pSrc->m_pScInt, v + 1 ) == 0, "?" );
    CHECK( SymCryptIntIsEqualUint32( pSrc->m_pScInt, v - 1 ) == 0, "?" );
}

VOID
testIsEqual()
{
    BYTE            buf1[MAX_INT_BYTES];
    BYTE            buf2[MAX_INT_BYTES];
    SYMCRYPT_ERROR  scError;
    SIZE_T          nD1 = g_rng.sizet(1, g_digitLimit );
    SIZE_T          nD2 = g_rng.sizet(1, g_digitLimit );
    SIZE_T          nBytes1 = nD1 * g_bytesPerDigit;
    SIZE_T          nBytes2 = nD2 * g_bytesPerDigit;
    UINT32          expected;
    UINT32          mask;

    SIZE_T          nBytes = SYMCRYPT_MAX( nBytes1, nBytes2 );

    ArithInt    *pSrc1 = randomArithInt( nD1 );
    ArithInt    *pSrc2 = randomArithInt( nD2 );

    scError = SymCryptIntGetValue( pSrc1->m_pScInt, buf1, nBytes, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    scError = SymCryptIntGetValue( pSrc2->m_pScInt, buf2, nBytes, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    expected = memcmp( buf1, buf2, nBytes ) == 0 ? (UINT32)-1 : 0;

    mask = SymCryptIntIsEqual( pSrc1->m_pScInt, pSrc2->m_pScInt );

    CHECK( mask == expected, "Equality result not correct" );
}

VOID
testIsLessThan()
{
    BYTE            buf1[MAX_INT_BYTES];
    BYTE            buf2[MAX_INT_BYTES];
    SYMCRYPT_ERROR  scError;
    SIZE_T          nD1 = g_rng.sizet(1, g_digitLimit );
    SIZE_T          nD2 = g_rng.sizet(1, g_digitLimit );
    SIZE_T          nBytes1 = nD1 * g_bytesPerDigit;
    SIZE_T          nBytes2 = nD2 * g_bytesPerDigit;
    UINT32          expected;
    UINT32          mask;

    SIZE_T          nBytes = SYMCRYPT_MAX( nBytes1, nBytes2 );

    ArithInt    *pSrc1 = randomArithInt( nD1 );
    ArithInt    *pSrc2 = randomArithInt( nD2 );

    scError = SymCryptIntGetValue( pSrc1->m_pScInt, buf1, nBytes, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    scError = SymCryptIntGetValue( pSrc2->m_pScInt, buf2, nBytes, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    expected = 0;
    for( SIZE_T i=0; i<nBytes; i++ )
    {
        if( buf1[i] < buf2[i] )
        {
            expected = (UINT32)-1;
            break;
        } else if( buf1[i] > buf2[i] )
        {
            expected = 0;
            break;
        }
    }

    mask = SymCryptIntIsLessThan( pSrc1->m_pScInt, pSrc2->m_pScInt );

    CHECK( mask == expected, "Comparison result not correct" );
}

VOID
testIntDivPow2()
{
    BYTE    bufSrc[ MAX_INT_BYTES ];

    SIZE_T      nD = g_rng.sizet(1, g_digitLimit );
    SIZE_T      nBytes = nD * g_bytesPerDigit;
    UINT32      w;


    ArithInt    *pSrc = randomArithInt( nD );
    ArithInt    *pDst = randomArithInt( nD );

    pDst->checkWoop();

    SIZE_T exp = g_rng.sizet( (nD+2) * g_bitsPerDigit );

    SymCryptIntGetValue( pSrc->m_pScInt, bufSrc, nBytes, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST );

    SymCryptIntDivPow2( pSrc->m_pScInt, exp, pDst->m_pScInt );

    if( exp == 0 )
    {
        w = pSrc->m_woop;
    }
    else if( exp >= nD * g_bitsPerDigit )
    {
        w = 0;
    } else
    {
        SIZE_T partialByteIndex = exp / 8;

        SIZE_T i = nBytes - 1;
        w = 0;
        while( i > partialByteIndex )
        {
            w = (((UINT64)w << 8 ) + bufSrc[i] ) % g_woopMod;
            i--;
        }

        w = ((((UINT64)w << 8 ) + bufSrc[i] ) >> (exp % 8) ) % g_woopMod;
    }
    pDst->m_woop = w;
    TEST_CHECK_WOOP( pDst );
}

VOID
testIntMulUint32()
{
    SIZE_T      nD = g_rng.sizet(1, g_digitLimit );
    UINT32      v;
    ArithInt    *pSrc = randomArithInt( nD );
    ArithInt    *pDst = randomArithInt( nD );
    UINT32      r;
    UINT64      t;

    v = g_rng.uint32();

    pDst->checkWoop();
    r = SymCryptIntMulUint32( pSrc->m_pScInt, v, pDst->m_pScInt );

    t = ((UINT64)pSrc->m_woop * v) + g_woopMod;
    t -= ((UINT64)r * g_carryWoop[nD] ) % g_woopMod;

    pDst->m_woop = (UINT32)(t % g_woopMod);

    TEST_CHECK_WOOP( pDst );
}

VOID
testIntMulSameSize()
{
    SIZE_T  nD = g_rng.sizet( 1, (g_digitLimit+1)/2 );  // limit is an exclusive upper bound, which means we have to round up when it is odd.

    ArithInt    *pSrc1 = randomArithInt( nD );
    ArithInt    *pSrc2 = randomArithInt( nD );
    ArithInt    *pDst  = randomArithInt( 2*nD );

    pDst->checkWoop();

    SymCryptIntMulSameSize( pSrc1->m_pScInt, pSrc2->m_pScInt, pDst->m_pScInt, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_INT_MUL( 2*nD ) );
    pDst->m_woop = (UINT32)(((UINT64) pSrc1->m_woop * pSrc2->m_woop ) % g_woopMod);

    TEST_CHECK_WOOP( pDst );
}

VOID
testIntMulMixedSize()
{
    SIZE_T  nDd = g_rng.sizet( 2, g_digitLimit );
    SIZE_T  nD1 = g_rng.sizet( 1, nDd );
    SIZE_T  nD2 = g_rng.sizet( 1, nDd - nD1 + 1);

    SYMCRYPT_ASSERT( nD2 > 0 );
    SYMCRYPT_ASSERT( nDd != nD1 );
    SYMCRYPT_ASSERT( nDd != nD2 );

    ArithInt    *pSrc1 = randomArithInt( nD1 );
    ArithInt    *pSrc2 = randomArithInt( nD2 );
    ArithInt    *pDst  = randomArithInt( nDd );

    pDst->checkWoop();

    SymCryptIntMulMixedSize( pSrc1->m_pScInt, pSrc2->m_pScInt, pDst->m_pScInt, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_INT_MUL( nDd ) );
    pDst->m_woop = (UINT32)(((UINT64) pSrc1->m_woop * pSrc2->m_woop ) % g_woopMod);

    TEST_CHECK_WOOP( pDst );
}

VOID
testIntSquare()
{
    SIZE_T  nD = g_rng.sizet( 1, (g_digitLimit+1)/2 );  // limit is an exclusive upper bound, which means we have to round up when it is odd.

    ArithInt    *pSrc1 = randomArithInt( nD );
    ArithInt    *pDst  = randomArithInt( 2*nD );

    pDst->checkWoop();

    SymCryptIntSquare( pSrc1->m_pScInt, pDst->m_pScInt, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_INT_MUL( 2*nD ) );
    pDst->m_woop = (UINT32)(((UINT64) pSrc1->m_woop * pSrc1->m_woop ) % g_woopMod);

    TEST_CHECK_WOOP( pDst );
}

#define BYTES_TO_DIGITS(x)  (((x) + (sizeof(digit_t) - 1)) / sizeof(digit_t))

VOID
testIntPrimalityTest()
{
    SYMCRYPT_ERROR  scError = SYMCRYPT_NO_ERROR;
    UINT32          nFail = 0;
    BYTE            rand = 0;

    ArithInt       *pSrc = NULL;
    UINT32          nD = 0;
    PSYMCRYPT_INT   piSrc = NULL;
    UINT32          cbSrc = 0;

    const SIZE_T    cbBuf = SYMCRYPT_SIZEOF_INT_FROM_BITS( 32 );
    BYTE            rawbuf[ cbBuf ];
    PBYTE           pbBuf = SYMCRYPT_ASYM_ALIGN_UP( rawbuf );
    PBYTE           pbScratch = g_scratch;
    SIZE_T          cbScratch = sizeof( g_scratch );

    PCBYTE          pCurr = NULL;
    UINT32          nBytes = 0;
    UINT32          index = 0;

    UINT32          primActual = 0;
    UINT32          primResult = 0;

    UINT32          flags = 0;

    //
    // - With probability 12.5% pick a known prime and verify
    //   that the test outputs "prime".
    // - With probability 12.5% pick a known composite and verify
    //   that the test outputs "composite".
    // - With prob 12.5%, pick a small integer to test
    // - Otherwise compare the result of the
    //   SymCrypt primality test with the reference primality test.
    //

    rand = g_rng.byte() & 0x07;
    if ( rand < 2 )
    {
        if ( rand == 0 )
        {
            // Known prime
            primActual = 0xffffffff;
        }
        else
        {
            // Known composite
            primActual = 0;
        }

        // Pick number of digits
        do
        {
            nD = (UINT32)g_rng.sizet( 1, g_digitLimit );
        }
        while (
                (primActual && !isPrimePossible(nD) ) ||
                (!primActual && !isCompositePossible(nD) )
              );

        // Create the integer
        cbSrc = SymCryptSizeofIntFromDigits( nD );
        piSrc = SymCryptIntCreate( g_scratch, cbSrc, nD );
        CHECK( piSrc != NULL, "?" );

        // Pick a random composite or prime number
        if( primActual )
        {
            // pick a prime
            do {
                index = (UINT32) g_rng.sizet( g_nTestPrimes );
            } while( 8 * g_testPrimes[index].nBytes > nD * g_bitsPerDigit );

            pCurr = g_testPrimes[ index ].pPrime;
            nBytes = g_testPrimes[ index ].nBytes;
        }
        else
        {
            // pick a composite
            do {
                index = (UINT32) g_rng.sizet( g_nTestComposites );
            } while( 8 * g_testComposites[index].nBytes > nD * g_bitsPerDigit );

            pCurr = g_testComposites[ index ].pComposite;
            nBytes = g_testComposites[ index ].nBytes;
        }

        // Set the value
        scError = SymCryptIntSetValue( pCurr, nBytes, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piSrc );
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

        // Set the flags to always be non-side channel safe if the number is not 3 mod 4
        // Otherwise set not side-channel safe with probability 50%.
        if ( (SymCryptIntGetBits(piSrc, 0, 2) != 3) ||
             (g_rng.byte() & 1) )
        {
            flags = SYMCRYPT_FLAG_DATA_PUBLIC;
        }
        //iprint( "[%s %d]", primActual ? "prime" : "composite", nD );
    }
    else if( rand == 3 )
    {
        // Pick a random 32-bit prime; lots of strange corner-cases happen more often
        // in small primes.
        nD = 1;
        piSrc = SymCryptIntCreate( pbBuf, cbBuf, SymCryptDigitsFromBits( 32 ) );
        CHECK( piSrc != NULL, "?" );
        do {
            index = g_rng.uint32();
            index |= 1;
        } while( index < 5 );
        SymCryptIntSetValueUint32( index, piSrc );
        primActual = RefIsPrime( piSrc, pbScratch, cbScratch ) ? 0xffffffff : 0;
        flags = g_rng.uint32() & SYMCRYPT_FLAG_DATA_PUBLIC;

        // Current SymCrypt can only do non-public values if they are 3 mod 4
        if( (index & 2) == 0 )
        {
            flags |= SYMCRYPT_FLAG_DATA_PUBLIC;
        }

        //iprint( "[%d]", index );
    } else
    {
        // Pick number of digits
        nD = (UINT32) g_rng.sizet( 1, g_digitLimit );

        // Pick flags
        if (g_rng.byte() & 1)
        {
            flags = SYMCRYPT_FLAG_DATA_PUBLIC;
        }

        // Pick a random integer which is greater than 3 and odd
        // ** And when we have side-channel safety to be 3 mod 4
        nFail = 0;
        do
        {
            pSrc = randomArithInt( nD, nFail++ );
        } while ( (SymCryptIntBitsizeOfValue(pSrc->m_pScInt)<3) ||
                  (!SymCryptIntGetBit(pSrc->m_pScInt, 0)) ||
                  (!flags && !SymCryptIntGetBit(pSrc->m_pScInt, 1)) );

        // Set the value
        piSrc = pSrc->m_pScInt;

        primActual = RefIsPrime( piSrc, pbScratch, cbScratch ) ? 0xffffffff : 0;
        //iprint( "[rnd]");
    }

    // Check for primality
    primResult = SymCryptIntMillerRabinPrimalityTest(
                        piSrc,
                        SymCryptIntBitsizeOfValue( piSrc ),
                        64, // nIterations
                        flags,
                        g_scratch + cbSrc,
                        SYMCRYPT_SCRATCH_BYTES_FOR_INT_IS_PRIME( nD ) );

    if ((rand < 2) || (SymCryptIntBitsizeOfValue(piSrc)>2))
    {
        CHECK4(primResult == primActual, "Primality test produced wrong result\n  Result : 0x%x\n  Desired: 0x%x", primResult, primActual);
    }

}

//=================================
// Divisor

ArithDivisor::ArithDivisor( SIZE_T nDigits, UINT32 nFail )
{
    SIZE_T nBytes;
    UINT32 nBits;
    ArithInt *pSrc = NULL;
    UINT32 nLocalFail;

    nLocalFail = 0;
    do {
        pSrc = randomArithInt( nDigits, nFail + nLocalFail );
        nLocalFail++;
    } while( SymCryptIntIsEqualUint32( pSrc->m_pScInt, 0 ) );

    m_nDigits = (UINT32) nDigits;
    CHECK( m_nDigits == nDigits, "?" );

    if( (g_rng.byte() & 1) == 0 )
    {
        // Use the SymCrypt allocator
        m_pAllocated = NULL;
        m_pScDivisor = SymCryptDivisorAllocate( (UINT32) nDigits );
        CHECK( m_pScDivisor != NULL, "Error during INT allocation" );
    } else {
        // Use our own memory buffer, and add magics around it to detect overruns.

        nBytes = SymCryptSizeofDivisorFromDigits( (UINT32) nDigits );

        nBits = 0;
        while( SymCryptDigitsFromBits( nBits + 1 ) <= nDigits )
        {
            nBits++;
        }
        CHECK3( nBytes <= SYMCRYPT_SIZEOF_DIVISOR_FROM_BITS( nBits ), "Size mismatch %d", nBits );

        m_pAllocated = (PBYTE) AllocWithChecksSc( nBytes );
        m_cbAllocated = nBytes;

        //
        // Set to zero so that we can test the SymcryptWipe later
        //
        SymCryptWipe( m_pAllocated, nBytes );

        m_pScDivisor = SymCryptDivisorCreate( (PBYTE) m_pAllocated, nBytes, (UINT32) nDigits );
        CHECK( m_pScDivisor != NULL, "Error during INT creation" );
    }

    SymCryptIntToDivisor( pSrc->m_pScInt, m_pScDivisor, 0, 0, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_DIVISOR( nDigits ) );
    m_woop = pSrc->m_woop;

    InterlockedIncrement64( &m_nArithDivisorObjects );
}

ArithDivisor::~ArithDivisor()
{
    InterlockedDecrement64( &m_nArithDivisorObjects );

    if( m_pAllocated == NULL )
    {
        SymCryptDivisorFree( m_pScDivisor );
        m_pScDivisor = NULL;
    } else {
        SymCryptDivisorWipe( m_pScDivisor );
        m_pScDivisor = NULL;

        BYTE b = 0;
        for( SIZE_T i=0; i<m_cbAllocated; i++ )
        {
            b |= m_pAllocated[i];
        }
        CHECK( b == 0, "SymCryptDivisorWipe did not wipe everything" );

        FreeWithChecksSc( m_pAllocated );
        m_pAllocated = NULL;
    }

}

VOID
testDivisorObjectLifetime()
{
    SIZE_T  nD = g_rng.sizet( 1, g_digitLimit );
    SIZE_T  n = g_divisorObjectVector[nD].size();

    // decide if we will add or remove an object
    SIZE_T  r = g_rng.sizet( 2 * g_nDivisorPerVectorTarget );

    if( r < n )
    {
        // Remove an item
        SIZE_T index = g_rng.sizet(n);
        ArithDivisor * p = g_divisorObjectVector[nD][index];
        g_divisorObjectVector[nD].erase( g_divisorObjectVector[nD].begin() + index );
        delete p;
        dprint( "Divisor[%d]=%d remove, ", (int) nD, (int) n );
    } else {
        // Add an item
        g_divisorObjectVector[nD].push_back( new ArithDivisor( nD ) );
        dprint( "Divisor[%d]=%d add, ", (int) nD, (int) n );
    }
}

VOID
initDivisorObjects()
{
    g_nDivisorPerVectorTarget = 100;
    CHECK( g_digitLimit <= MAX_INT_DIGITS_STATIC + 1, "?" );
}

VOID
cleanupDivisorObjects()
{
    for( UINT32 i=1; i < g_digitLimit; i++ )
    {
        while( !g_divisorObjectVector[i].empty() )
        {
            delete g_divisorObjectVector[i].back();
            g_divisorObjectVector[i].pop_back();
        }
    }

    CHECK( ArithDivisor::m_nArithDivisorObjects == 0, "Not all int objects deleted" );
}

ArithDivisor *
randomArithDivisor( SIZE_T nD, UINT32 nFail = 0 )
{
    ArithDivisor * res = NULL;
    SIZE_T n;

    CHECK( nD < g_digitLimit, "too many digits" );
    n = g_divisorObjectVector[nD].size();

    if( n == 0 || nFail > 10 )
    {
        // Add an item
        res = new ArithDivisor( nD, nFail );
        g_divisorObjectVector[nD].push_back( res );
        dprint( "[created Divisor(%d)]", (int)nD );
    } else {
        res = g_divisorObjectVector[nD][g_rng.sizet(n)];
    }

    return res;
}

VOID
testDivisorCopy()
{
    SIZE_T nD = g_rng.sizet( 1, g_digitLimit );

    ArithDivisor *pSrc = randomArithDivisor( nD );
    ArithDivisor *pDst  = randomArithDivisor( nD );

    SymCryptDivisorCopy( pSrc->m_pScDivisor, pDst->m_pScDivisor );
    pDst->m_woop = pSrc->m_woop;
}

VOID
testIntDivMod()
{
    SIZE_T ndNum = g_rng.sizet( 1, g_digitLimit );
    SIZE_T ndDiv;
    SIZE_T ndQuot;
    SIZE_T ndRem;
    UINT32 nFail;

    // For more efficient test coverage, we use a numerator that is shorter than the denominator only 10% of the time
    if( g_rng.byte() < 25 )
    {
        ndDiv = g_rng.sizet( 1, ndNum + 1 );
    } else {
        ndDiv = g_rng.sizet( ndNum, g_digitLimit );
    }

    // Digit sizes for quotient and remainder
    ndQuot = g_rng.sizet( ndNum, g_digitLimit );
    ndRem = g_rng.sizet( ndDiv, g_digitLimit );

    ArithInt *pNum = randomArithInt( ndNum );
    ArithDivisor *pDiv = randomArithDivisor( ndDiv );
    ArithInt * pQuotient = NULL;
    ArithInt * pRemainder = NULL;

    nFail = 0;
    do{
        pQuotient = randomArithInt( ndQuot, nFail++ );
    } while( pQuotient == pNum );

    nFail = 0;
    do{
        pRemainder = randomArithInt( ndRem, nFail++ );
    } while( pRemainder == pQuotient || pRemainder == pNum );

    pQuotient->checkWoop();
    pRemainder->checkWoop();

    SymCryptIntDivMod( pNum->m_pScInt, pDiv->m_pScDivisor, pQuotient->m_pScInt, pRemainder->m_pScInt, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD( ndNum, ndDiv ) );

    pQuotient->m_woop = pQuotient->computeWoop();

    pRemainder->m_woop = pRemainder->computeWoop();

    CHECK( ((UINT64) pQuotient->m_woop * pDiv->m_woop + pRemainder->m_woop) % g_woopMod == pNum->m_woop, "Woop mismatch on divmod" );

    TEST_CHECK_WOOP( pQuotient );
    TEST_CHECK_WOOP( pRemainder );
}

VOID
testIntGcdEx()
{
    UINT32  nD1 = (UINT32)g_rng.sizet( 1, g_digitLimit );
    UINT32  nD2 = (UINT32)g_rng.sizet( 1, g_digitLimit );

    UINT32 nFail = 0;

    ArithDivisor *pSrc1 = NULL;
    ArithDivisor *pSrc2 = NULL;

    UINT32              ndGcd= 0;
    PSYMCRYPT_DIVISOR   pdGcd = NULL;
    UINT32              cbGcd = 0;

    UINT32              ndLarge = 0;
    PSYMCRYPT_INT       piLarge = NULL;
    UINT32              cbLarge = 0;

    UINT32              ndRemainder = 0;
    PSYMCRYPT_INT       piRemainder = NULL;
    UINT32              cbRemainder = 0;

    PBYTE               pbTmp = g_scratch;

    PSYMCRYPT_INT       piSrc1 = NULL;
    PSYMCRYPT_INT       piSrc2 = NULL;
    PSYMCRYPT_INT       piGcd = NULL;
    PSYMCRYPT_INT       piLcm = NULL;
    PSYMCRYPT_INT       piInvSrc1ModSrc2 = NULL;
    PSYMCRYPT_INT       piInvSrc2ModSrc1 = NULL;

    BYTE rand = g_rng.byte() & 0x03;

    //
    // This routine tests the SymCryptIntExtendedGcd algorithm in the following way:
    //
    // First it picks two random non-zero divisors Src1 and Src2, with Src2 odd. Then
    // it checks if one divides the other.
    //
    // If Src1 divides Src2, it calls SymCryptIntExtendedGcd with outputs gcd and lcm and
    // verifies that gcd == Src1 and lcm == Src2.
    //
    // If Src2 divides Src1, it calls SymCryptIntExtendedGcd with outputs gcd and lcm and
    // verifies that gcd == Src2 and lcm == Src1.
    //
    // In all other cases, it calls SymCryptIntExtendedGcd with outputs gcd and one of
    // the following:
    //
    //    - With probability 50% it calculates the least common multiple of Src1 and Src2 and
    //      verifies that Src1 or Src2 divides the result (each with total probability 25%).
    //    - With probability 25% it calculates the inverse of Src1 modulo Src2 and verifies
    //      that the result multiplied by Src1 is equal to GCD modulo Src2.
    //    - With probability 25% it calculates the inverse of Src2 modulo Src1 and verifies
    //      that the result multiplied by Src2 is equal to GCD modulo Src1.
    //

    // Src1
    pSrc1 = randomArithDivisor( nD1 );
    piSrc1 = SymCryptIntFromDivisor( pSrc1->m_pScDivisor );

    // Src2
    nFail = 0;
    do
    {
        pSrc2 = randomArithDivisor( nD2, nFail++ );
        piSrc2 = SymCryptIntFromDivisor( pSrc2->m_pScDivisor );
    } while ( (SymCryptIntGetValueLsbits32(piSrc2) & 0x01) == 0);

    ndGcd = SYMCRYPT_MIN(nD1,nD2);
    ndLarge = 2*SYMCRYPT_MAX(nD1,nD2);       // Big enough for LCM and the products InvSrcXModSrcY * SrcX
    ndRemainder = SYMCRYPT_MAX(nD1,nD2);     // Big enough for remainders modulo Src1 and Src2

    cbGcd = SymCryptSizeofDivisorFromDigits( ndGcd );
    pdGcd = SymCryptDivisorCreate( pbTmp, cbGcd, ndGcd );
    pbTmp += cbGcd;

    cbLarge = SymCryptSizeofIntFromDigits( ndLarge );
    piLarge = SymCryptIntCreate( pbTmp, cbLarge, ndLarge );
    pbTmp += cbLarge;

    cbRemainder = SymCryptSizeofIntFromDigits( ndRemainder );
    piRemainder = SymCryptIntCreate( pbTmp, cbRemainder, ndRemainder );
    pbTmp += cbRemainder;

    piGcd = SymCryptIntFromDivisor( pdGcd );

    // First check if one divides the other
    SymCryptIntDivMod( piSrc2, pSrc1->m_pScDivisor, NULL, piRemainder, pbTmp, SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD( nD2, nD1 ));
    if (SymCryptIntIsEqualUint32( piRemainder, 0 ))
    {
        rand = 4;   // S1 divides S2
    }
    else
    {
        SymCryptIntDivMod( piSrc1, pSrc2->m_pScDivisor, NULL, piRemainder, pbTmp, SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD( nD1, nD2 ));
        if (SymCryptIntIsEqualUint32( piRemainder, 0 ))
        {
            rand = 5;   // S2 divides S1
        }
    }

    switch (rand)
    {
        case 0:
        case 1:
        case 4:
        case 5:
            piLcm = piLarge;
            break;
        case 2:
            piInvSrc1ModSrc2 = piRemainder;
            break;
        case 3:
            piInvSrc2ModSrc1 = piRemainder;
            break;
        default:
            CHECK( FALSE, "?" );
            break;
    }

    // Main function
    SymCryptIntExtendedGcd(
            piSrc1,
            piSrc2,
            0,
            piGcd,
            piLcm,
            piInvSrc1ModSrc2,
            piInvSrc2ModSrc1,
            pbTmp,
            SYMCRYPT_SCRATCH_BYTES_FOR_EXTENDED_GCD( SYMCRYPT_MAX( nD1, nD2 ) ) );

    // Verifications
    switch (rand)
    {
        case 0:
            SymCryptIntDivMod( piLcm, pSrc1->m_pScDivisor, NULL, piRemainder, pbTmp, SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD( ndLarge, nD1 ));
            CHECK( SymCryptIntIsEqualUint32( piRemainder, 0 ), "testIntGcdEx failed: Lcm %% Src1 != 0" );
            break;
        case 1:
            SymCryptIntDivMod( piLcm, pSrc2->m_pScDivisor, NULL, piRemainder, pbTmp, SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD( ndLarge, nD2 ));
            CHECK( SymCryptIntIsEqualUint32( piRemainder, 0 ), "testIntGcdEx failed: Lcm %% Src2 != 0" );
            break;

        case 2:
            SymCryptIntMulMixedSize( piSrc1, piInvSrc1ModSrc2, piLarge, pbTmp, SYMCRYPT_SCRATCH_BYTES_FOR_INT_MUL( ndLarge ) );
            SymCryptIntDivMod( piLarge, pSrc2->m_pScDivisor, NULL, piRemainder, pbTmp, SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD( ndLarge, nD2 ));
            CHECK( SymCryptIntIsEqual( piRemainder, piGcd ), "testIntGcdEx failed: InvSrc1ModSrc2 * Src1 != Gcd mod Src2" );
            break;
        case 3:
            SymCryptIntMulMixedSize( piSrc2, piInvSrc2ModSrc1, piLarge, pbTmp, SYMCRYPT_SCRATCH_BYTES_FOR_INT_MUL( ndLarge ) );
            SymCryptIntDivMod( piLarge, pSrc1->m_pScDivisor, NULL, piRemainder, pbTmp, SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD( ndLarge, nD1 ));
            CHECK( SymCryptIntIsEqual( piRemainder, piGcd ), "testIntGcdEx failed: InvSrc2ModSrc1 * Src2 != Gcd mod Src1" );
            break;

        case 4:
            CHECK( SymCryptIntIsEqual( piGcd, piSrc1 ), "testIntGcdEx failed: Gcd != Src1" );
            CHECK( SymCryptIntIsEqual( piLcm, piSrc2 ), "testIntGcdEx failed: Lcm != Src2" );
            break;
        case 5:
            CHECK( SymCryptIntIsEqual( piGcd, piSrc2 ), "testIntGcdEx failed: Gcd != Src2" );
            CHECK( SymCryptIntIsEqual( piLcm, piSrc1 ), "testIntGcdEx failed: Lcm != Src1" );
            break;

        default:
            CHECK( FALSE, "?" );
            break;
    }

    // Make sure that GCD divides both Src1 and Src2
    SymCryptIntToDivisor( piGcd, pdGcd, 2, 0, pbTmp, SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_DIVISOR( ndGcd ) );

    SymCryptIntDivMod( piSrc1, pdGcd, NULL, piRemainder, pbTmp, SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD( nD1, ndGcd ));
    CHECK( SymCryptIntIsEqualUint32( piRemainder, 0 ), "testIntGcdEx failed: Src1 %% Gcd != 0" );
    SymCryptIntDivMod( piSrc2, pdGcd, NULL, piRemainder, pbTmp, SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD( nD2, ndGcd ));
    CHECK( SymCryptIntIsEqualUint32( piRemainder, 0 ), "testIntGcdEx failed: Src2 %% Gcd != 0" );

}

//=================================
// Modulus

ArithModulus::ArithModulus( SIZE_T nDigits, UINT32 nFail )
{
    SIZE_T nBytes;
    UINT32 nBits;
    ArithInt *pSrc = NULL;
    UINT32 nLocalFail;
    UINT32 primeIndex;
    SYMCRYPT_ERROR scError;
    BYTE b;

    m_nDigits = (UINT32) nDigits;
    CHECK( m_nDigits == nDigits, "?" );

    if( (g_rng.byte() & 1) == 0 )
    {
        // Use the SymCrypt allocator
        m_pAllocated = NULL;
        m_pScModulus = SymCryptModulusAllocate( (UINT32) nDigits );
        CHECK( m_pScModulus != NULL, "Error during INT allocation" );
    } else {
        // Use our own memory buffer, and add magics around it to detect overruns.
        nBytes = SymCryptSizeofModulusFromDigits( (UINT32) nDigits );

        nBits = 0;
        while( SymCryptDigitsFromBits( nBits + 1 ) <= nDigits )
        {
            nBits++;
        }
        CHECK3( nBytes <= SYMCRYPT_SIZEOF_MODULUS_FROM_BITS( nBits ), "Size mismatch %d", nBits );

        m_pAllocated = (PBYTE) AllocWithChecksSc( nBytes );
        m_cbAllocated = nBytes;

        //
        // Set to zero so that we can test the SymcryptWipe later
        //
        SymCryptWipe( m_pAllocated, nBytes );

        m_pScModulus = SymCryptModulusCreate( (PBYTE) m_pAllocated, nBytes, (UINT32) nDigits );
        CHECK( m_pScModulus != NULL, "Error during INT creation" );
    }

    m_pScDivisor = SymCryptDivisorAllocate( (UINT32) nDigits );
    m_pScInt = SymCryptIntAllocate( (UINT32) nDigits );

    CHECK( m_pScDivisor != NULL && m_pScInt != NULL, "out of memory" );

    if( (g_rng.byte() & 1) == 0 || !isPrimePossible( (UINT32) nDigits ) )
    {
        // Pick one of the nonzero integers.
        // Sometimes we have other requirements, so we propagate the fail parameter to generate random values on repeated failures
        nLocalFail = 0;
        do {
            pSrc = randomArithInt( nDigits, nLocalFail + nFail );
            nLocalFail++;
        } while( SymCryptIntIsEqualUint32( pSrc->m_pScInt, 0 ) );

        SymCryptIntCopy( pSrc->m_pScInt, m_pScInt );

        m_flags = 0;
        b = g_rng.byte();
        if( b & 1 )
        {
            m_flags |= SYMCRYPT_FLAG_DATA_PUBLIC;
        }
        if( b & 2 )
        {
            m_flags |= SYMCRYPT_FLAG_MODULUS_PARITY_PUBLIC;
        }
        if( b & 4 )
        {
            m_flags |= SYMCRYPT_FLAG_MODULUS_ADDITIVE_ONLY;
        }

    } else {
        // pick a prime
        do {
            primeIndex = (UINT32) g_rng.sizet( g_nTestPrimes );
        } while( 8 * g_testPrimes[primeIndex].nBytes > nDigits * g_bitsPerDigit );
        scError = SymCryptIntSetValue( g_testPrimes[ primeIndex ].pPrime, g_testPrimes[ primeIndex ].nBytes, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, m_pScInt );
        m_flags = SYMCRYPT_FLAG_DATA_PUBLIC | SYMCRYPT_FLAG_MODULUS_PRIME;

        b = g_rng.byte();
        if( b & 1 )
        {
            m_flags |= SYMCRYPT_FLAG_DATA_PUBLIC;
        }
        if( b & 2 )
        {
            m_flags |= SYMCRYPT_FLAG_MODULUS_PARITY_PUBLIC;
        }
        if( b & 4 )
        {
            m_flags |= SYMCRYPT_FLAG_MODULUS_ADDITIVE_ONLY;
        }
        if( (b & 0xf0) != 0 )   // set the 'prime' flag most of the time
        {
            m_flags |= SYMCRYPT_FLAG_MODULUS_PRIME;
        }

        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    }

    SymCryptIntToModulus( m_pScInt, m_pScModulus, (1 << (g_rng.byte() & 0xf)), m_flags, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_MODULUS( nDigits ) );

    SymCryptIntToDivisor( m_pScInt, m_pScDivisor, 0, 0, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_DIVISOR( nDigits ) );

    InterlockedIncrement64( &m_nArithModulusObjects );
}

ArithModulus::~ArithModulus()
{
    InterlockedDecrement64( &m_nArithModulusObjects );

    // Delete all modelements
    while( !m_elVector.empty() )
    {
        delete m_elVector.back();
        m_elVector.pop_back();
    }

    SymCryptIntFree( m_pScInt );
    m_pScInt = NULL;

    SymCryptDivisorFree( m_pScDivisor );
    m_pScDivisor = NULL;

    if( m_pAllocated == NULL )
    {
        SymCryptModulusFree( m_pScModulus );
        m_pScModulus = NULL;
    } else {
        SymCryptModulusWipe( m_pScModulus );
        m_pScModulus = NULL;

        BYTE b = 0;
        for( SIZE_T i=0; i<m_cbAllocated; i++ )
        {
            b |= m_pAllocated[i];
        }
        CHECK( b == 0, "SymCryptModulusWipe did not wipe everything" );

        FreeWithChecksSc( m_pAllocated );
        m_pAllocated = NULL;
    }
}

ArithModulus *
randomArithModulus( SIZE_T nD, UINT32 nFail = 0 )
{
    ArithModulus * res = NULL;
    SIZE_T n;

    CHECK( nD < g_digitLimit, "too many digits" );
    n = g_modulusObjectVector[nD].size();

    if( n == 0 || nFail > 10 )
    {
        // Add an item
        res = new ArithModulus( nD, nFail );
        g_modulusObjectVector[nD].push_back( res );
        dprint( "[created Modulus(%d)]", (int)nD );
    } else {
        res = g_modulusObjectVector[nD][g_rng.sizet(n)];
    }

    return res;
}


VOID
testModulusObjectLifetime()
{
    SIZE_T  nD, n, r;

    // We don't modify the Modulus objects very often so that they have plenty of time to gather ModElements
    // and operate on them
    if( (g_rng.byte() & 0x7f) != 0 )
    {
        // do nothing 127/128 of the time
        goto cleanup;
    }

    nD = g_rng.sizet( 1, g_digitLimit );
    n = g_modulusObjectVector[nD].size();

    // decide if we will add or remove an object
    r = g_rng.sizet( 2 * g_nModulusPerVectorTarget );

    if( r < n )
    {
        // Remove an item
        SIZE_T index = g_rng.sizet(n);
        ArithModulus * p = g_modulusObjectVector[nD][index];
        g_modulusObjectVector[nD].erase( g_modulusObjectVector[nD].begin() + index );
        delete p;
        dprint( "Modulus[%d]=%d remove, ", (int) nD, (int) n );
    } else {
        // Add an item
        g_modulusObjectVector[nD].push_back( new ArithModulus( nD ) );
        dprint( "Modulus[%d]=%d add, ", (int) nD, (int) n );
    }

cleanup:
    return;
}

VOID
testModulusCopy()
{
    if( (g_rng.byte() & 0x7f) != 0 )
    {
        // Most of the time we skip this test, because we have to delete all the Dst modElements and
        // that throws away a bunch of values that we'd like to test more on.
        return;
    }
    SIZE_T nD = g_rng.sizet( 1, g_digitLimit );

    ArithModulus *pSrc = randomArithModulus( nD );
    ArithModulus *pDst = randomArithModulus( nD );

    // Delete all Dst modelements
    while( !pDst->m_elVector.empty() )
    {
        delete pDst->m_elVector.back();
        pDst->m_elVector.pop_back();
    }

    SymCryptModulusCopy( pSrc->m_pScModulus, pDst->m_pScModulus );
    SymCryptDivisorCopy( pSrc->m_pScDivisor, pDst->m_pScDivisor );
    SymCryptIntCopy( pSrc->m_pScInt, pDst->m_pScInt );
    pDst->m_flags = pSrc->m_flags;

    // Dst is left with an empty set of modElements.
    // We can't copy the ones from Src as modElementCopy is not defined between different moduli.
    // (We allow different moduli to use different internal representations.)
}


VOID
initModulusObjects()
{
    g_nModulusPerVectorTarget = 5;
}

VOID
cleanupModulusObjects()
{
    for( UINT32 i=1; i < g_digitLimit; i++ )
    {
        while( !g_modulusObjectVector[i].empty() )
        {
            delete g_modulusObjectVector[i].back();
            g_modulusObjectVector[i].pop_back();
        }
    }

    CHECK( ArithModulus::m_nArithModulusObjects == 0, "Not all modulus objects deleted" );
}


//=================================
// ModElement

ArithModElement * randomArithModElement( ArithModulus * pMod, UINT32 nFail );

ArithModElement::ArithModElement( ArithModulus * pModulus, UINT32 nFail )
{
    SIZE_T nBytes;
    UINT32 nBits;
    UINT32 nDigits = pModulus->m_nDigits;
    UINT32 nSrcDigits;
    ArithInt * pSrc;

    ArithModElement * pSrc1;
    ArithModElement * pSrc2;

    m_pModulus = pModulus;

    if( (g_rng.byte() & 1) == 0 )
    {
        // Use the SymCrypt allocator
        m_pAllocated = NULL;
        m_pScModElement = SymCryptModElementAllocate( pModulus->m_pScModulus );
        CHECK( m_pScModElement != NULL, "Error during INT allocation" );
    } else {
        // Use our own memory buffer, and add magics around it to detect overruns.

        nBytes = SymCryptSizeofModElementFromModulus( pModulus->m_pScModulus );

        nBits = 0;
        while( SymCryptDigitsFromBits( nBits + 1 ) <= nDigits )
        {
            nBits++;
        }
        CHECK3( nBytes <= SYMCRYPT_SIZEOF_MODELEMENT_FROM_BITS( nBits ), "Size mismatch %d", nBits );

        m_pAllocated = (PBYTE) AllocWithChecksSc( nBytes );
        m_cbAllocated = nBytes;

        m_pScModElement = SymCryptModElementCreate( (PBYTE) m_pAllocated, nBytes, pModulus->m_pScModulus );
        CHECK( m_pScModElement != NULL, "Error during INT creation" );
    }

    m_pScInt = SymCryptIntAllocate( nDigits );
    m_pScTmp1 = SymCryptIntAllocate( 1*nDigits );
    m_pScTmp2 = SymCryptIntAllocate( 2*nDigits );

    CHECK( m_pScInt != NULL && m_pScTmp1 != NULL && m_pScTmp2 != NULL, "Out of memory" );

    if( (g_rng.byte() & 7) == 0 )
    {
        // With probability 12.5% pick the value of the new element by
        // adding the values of two existing elements.
        //
        // This way we bypass the SymCryptIntToModElement call (on the other
        // branch) which zeros all the higher-order bits of the destination
        // modelement.
        //
        // By calling SymCryptModAdd we make sure that the higher-order bits
        // of the destination modelement are always correct.

        pSrc1 = randomArithModElement( pModulus, nFail );
        pSrc2 = randomArithModElement( pModulus, nFail );

        SymCryptModAdd(
            pModulus->m_pScModulus,
            pSrc1->m_pScModElement,
            pSrc2->m_pScModElement,
            m_pScModElement,
            g_scratch,
            SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ) );

        SymCryptModElementToInt(
            pModulus->m_pScModulus,
            m_pScModElement,
            m_pScInt,
            g_scratch,
            SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ) );
    }
    else
    {
        // Pick a random Int value of the right size. Our Int values contain the low-Hamming-weight and small values we need for corner cases.

        nSrcDigits = 1 + (UINT32)g_rng.sizet( 2 * nDigits );                // compute this once (min might be a macro)
        nSrcDigits = SYMCRYPT_MIN( nSrcDigits, g_digitLimit - 1);
        pSrc = randomArithInt( nSrcDigits, nFail );

        SymCryptIntToModElement( pSrc->m_pScInt, m_pModulus->m_pScModulus, m_pScModElement,g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ) );

        // Now keep track of the expected value
        SymCryptIntDivMod( pSrc->m_pScInt, m_pModulus->m_pScDivisor, NULL, m_pScInt, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD( nSrcDigits, nDigits ) );
    }

    //if( g_rng.byte() & 1 )
    {
        // Negate the value to get values close to the prime

    }

    InterlockedIncrement64( &m_nArithModElementObjects );

    TEST_CHECK_VALUE( this );
}

VOID
ArithModElement::checkValue()
{
    UINT32 nBytes = m_pModulus->m_nDigits * (UINT32)g_bytesPerDigit;
    SYMCRYPT_ERROR scError;

    scError = SymCryptModElementGetValue(
                        m_pModulus->m_pScModulus,
                        m_pScModElement,
                        g_scratch,
                        nBytes,
                        SYMCRYPT_NUMBER_FORMAT_LSB_FIRST,
                        &g_scratch[nBytes],
                        SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( m_pModulus->m_nDigits ) );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    scError = SymCryptIntGetValue( m_pScInt, &g_scratch[nBytes], nBytes, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    CHECK( memcmp( g_scratch, &g_scratch[nBytes], nBytes ) == 0, "ModElement value mismatch" );
}

ArithModElement::~ArithModElement()
{
    // Check the value
    checkValue();

    if( m_pAllocated == NULL )
    {
        SymCryptModElementFree( m_pModulus->m_pScModulus, m_pScModElement );
        m_pScModElement = NULL;
    } else {
        SymCryptModElementWipe( m_pModulus->m_pScModulus, m_pScModElement );
        m_pScModElement = NULL;

        BYTE b = 0;
        for( SIZE_T i=0; i<m_cbAllocated; i++ )
        {
            b |= m_pAllocated[i];
        }
        CHECK( b == 0, "SymCryptModElementWipe did not wipe everything" );

        FreeWithChecksSc( m_pAllocated );
        m_pAllocated = NULL;
    }
    SymCryptIntFree( m_pScInt );
    SymCryptIntFree( m_pScTmp1 );
    SymCryptIntFree( m_pScTmp2 );

    InterlockedDecrement64( &m_nArithModElementObjects );
}

VOID
initModElementObjects()
{
    g_nModElementPerVectorTarget = 25;
}

VOID
cleanupModElementObjects()
{
}

VOID
testModElementObjectLifetime()
{
    SIZE_T  nD = g_rng.sizet( 1, g_digitLimit );

    ArithModulus * pMod = randomArithModulus( nD );
    SIZE_T n = pMod->m_elVector.size();

    // decide if we will add or remove an object
    SIZE_T  r = g_rng.sizet( 2 * g_nModElementPerVectorTarget );

    if( r < n )
    {
        // Remove an item
        SIZE_T index = g_rng.sizet(n);
        ArithModElement * p = pMod->m_elVector[index];
        pMod->m_elVector.erase( pMod->m_elVector.begin() + index );
        delete p;
        dprint( "ModElement[%d]=%d remove, ", (int) nD, (int) n );
    } else {
        // Add an item
        pMod->m_elVector.push_back( new ArithModElement( pMod ) );
        dprint( "ModElement[%d]=%d add, ", (int) nD, (int) n );
    }

}

ArithModElement *
randomArithModElement( ArithModulus * pMod, UINT32 nFail = 0 )
{
    ArithModElement * res = NULL;

    SIZE_T n = pMod->m_elVector.size();

    if( n == 0 || nFail > 10 )
    {
        // Add an item
        res = new ArithModElement( pMod, nFail );
        pMod->m_elVector.push_back( res );
        dprint( "[created ModElement]" );
    } else {
        res = pMod->m_elVector[g_rng.sizet(n)];
    }

    return res;
}

VOID
testModElementCopy()
{
    SIZE_T nD = g_rng.sizet( 1, g_digitLimit );

    ArithModulus *pMod = randomArithModulus( nD );

    ArithModElement *pSrc = randomArithModElement( pMod );
    ArithModElement *pDst = randomArithModElement( pMod );

    CHECK( pSrc->m_pModulus == pDst->m_pModulus, "Different moduli" );

    SymCryptModElementCopy( pMod->m_pScModulus, pSrc->m_pScModElement, pDst->m_pScModElement );
    SymCryptIntCopy( pSrc->m_pScInt, pDst->m_pScInt );
}

VOID
testModElementSetValue()
{
    SIZE_T nD = g_rng.sizet( 1, g_digitLimit );

    //
    // We get our value from the Ints as they contain many interesting corner cases
    // As well as values close to the modulus as the modulus also comes from that set.
    //

    ArithInt *pSrc = randomArithInt( nD );
    ArithModulus *pMod = randomArithModulus( nD );
    ArithModElement *pDst = randomArithModElement( pMod );

    BYTE                    buf[MAX_INT_BYTES];
    SYMCRYPT_NUMBER_FORMAT  format;
    UINT32                  nBytes = pSrc->m_nDigits * g_bytesPerDigit;

    if( (g_rng.byte() & 1) == 0 )
    {
        format = SYMCRYPT_NUMBER_FORMAT_LSB_FIRST;
    } else {
        format = SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
    }

    SymCryptIntGetValue( pSrc->m_pScInt, buf, nBytes, format );

    SymCryptModElementSetValue( buf, nBytes, format, pMod->m_pScModulus, pDst->m_pScModElement, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nD ));
    SymCryptIntCopy( pSrc->m_pScInt, pDst->m_pScInt );
    SymCryptIntDivMod( pDst->m_pScInt, pMod->m_pScDivisor, NULL, pDst->m_pScInt, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nD ) );
}

VOID
testModElementSetValueUint32()
{
    SIZE_T nD = g_rng.sizet( 1, g_digitLimit );

    ArithModulus *pMod = randomArithModulus( nD );
    ArithModElement *pDst = randomArithModElement( pMod );

    UINT32 nBits = SymCryptIntBitsizeOfValue( pMod->m_pScInt );
    UINT32 value;

    if( nBits <= 32 )
    {
        value = (UINT32)g_rng.sizet( SymCryptIntGetValueLsbits32( pMod->m_pScInt ) );
    } else {
        value = g_rng.uint32();
    }

    SymCryptModElementSetValueUint32( value, pMod->m_pScModulus, pDst->m_pScModElement, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nD ));
    SymCryptIntSetValueUint32( value, pDst->m_pScInt );
}

VOID
testModElementSetValueNegUint32()
{
    // SetValueNegUint32 isn't allowed for value == 0
    SIZE_T nD = g_rng.sizet( 1, g_digitLimit );
    ArithModulus *pMod;

    UINT32 nFail;

    // Choose a modulus that isn't equal to 1
    nFail = 0;
    do {
        pMod = randomArithModulus( nD, nFail++ );
    } while( SymCryptIntIsEqualUint32( pMod->m_pScInt, 1 ) );       // repeat as long as the result is equal to 1

    ArithModElement *pDst = randomArithModElement( pMod );

    UINT32 nBits = SymCryptIntBitsizeOfValue( pMod->m_pScInt );
    UINT32 value;

    value = 0;
    while( value == 0 )
    {
        if( nBits <= 32 )
        {
            value = (UINT32)g_rng.sizet( SymCryptIntGetValueLsbits32( pMod->m_pScInt ) );
        } else {
            value = g_rng.uint32();
        }
    }

    SymCryptModElementSetValueNegUint32( value, pMod->m_pScModulus, pDst->m_pScModElement, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nD ));
    SymCryptIntSetValueUint32( value, pDst->m_pScTmp1 );
    SymCryptIntSubSameSize( pMod->m_pScInt, pDst->m_pScTmp1, pDst->m_pScInt );
}

VOID
testModAdd()
{
    SIZE_T nD = g_rng.sizet( 1, g_digitLimit );

    ArithModulus *pMod = randomArithModulus( nD );

    ArithModElement *pSrc1 = randomArithModElement( pMod );
    ArithModElement *pSrc2 = randomArithModElement( pMod );
    ArithModElement *pDst  = randomArithModElement( pMod );

    //pSrc1->checkValue();
    //pSrc2->checkValue();
    pDst->checkValue();

    SymCryptModAdd( pMod->m_pScModulus, pSrc1->m_pScModElement, pSrc2->m_pScModElement, pDst->m_pScModElement, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nD ) );
    UINT32 ca = SymCryptIntAddSameSize( pSrc1->m_pScInt, pSrc2->m_pScInt, pDst->m_pScInt );
    UINT32 cs;
    if( ca != 0 || !SymCryptIntIsLessThan( pDst->m_pScInt, pMod->m_pScInt ) )
    {
        cs = SymCryptIntSubSameSize( pDst->m_pScInt, pMod->m_pScInt, pDst->m_pScInt );
        CHECK( ca == cs, "?" );
    }

    TEST_CHECK_VALUE( pDst );
}

VOID
testModSub()
{
    SIZE_T nD = g_rng.sizet( 1, g_digitLimit );

    ArithModulus *pMod = randomArithModulus( nD );

    ArithModElement *pSrc1 = randomArithModElement( pMod );
    ArithModElement *pSrc2 = randomArithModElement( pMod );
    ArithModElement *pDst  = randomArithModElement( pMod );

    pDst->checkValue();

    SymCryptModSub( pMod->m_pScModulus, pSrc1->m_pScModElement, pSrc2->m_pScModElement, pDst->m_pScModElement, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nD ) );
    UINT32 cs = SymCryptIntSubSameSize( pSrc1->m_pScInt, pSrc2->m_pScInt, pDst->m_pScInt );
    UINT32 ca;
    if( cs != 0 )
    {
        ca = SymCryptIntAddSameSize( pDst->m_pScInt, pMod->m_pScInt, pDst->m_pScInt );
        CHECK( ca == cs, "?" );
    }

    TEST_CHECK_VALUE( pDst );
}

VOID
testModMul()
{
    SIZE_T nD = g_rng.sizet( 1, g_digitLimit );

    ArithModulus *pMod = randomArithModulus( nD );

    ArithModElement *pSrc1 = randomArithModElement( pMod );
    ArithModElement *pSrc2 = randomArithModElement( pMod );
    ArithModElement *pDst  = randomArithModElement( pMod );

    pDst->checkValue();

    SymCryptModMul( pMod->m_pScModulus, pSrc1->m_pScModElement, pSrc2->m_pScModElement, pDst->m_pScModElement, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nD ) );

    SymCryptIntMulSameSize( pSrc1->m_pScInt, pSrc2->m_pScInt, pDst->m_pScTmp2, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nD ) );
    SymCryptIntDivMod( pDst->m_pScTmp2, pMod->m_pScDivisor, pDst->m_pScTmp2, pDst->m_pScInt, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nD ) );

    TEST_CHECK_VALUE( pDst );
}

VOID
testModSquare()
{
    SIZE_T nD = g_rng.sizet( 1, g_digitLimit );

    ArithModulus *pMod = randomArithModulus( nD );

    ArithModElement *pSrc1 = randomArithModElement( pMod );
    ArithModElement *pDst  = randomArithModElement( pMod );

    pDst->checkValue();

    SymCryptModSquare( pMod->m_pScModulus, pSrc1->m_pScModElement, pDst->m_pScModElement, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nD ) );

    SymCryptIntSquare( pSrc1->m_pScInt, pDst->m_pScTmp2, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nD ) );
    SymCryptIntDivMod( pDst->m_pScTmp2, pMod->m_pScDivisor, pDst->m_pScTmp2, pDst->m_pScInt, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nD ) );

    TEST_CHECK_VALUE( pDst );
}

VOID
testModDivPow2()
{
    SIZE_T nD = g_rng.sizet( 1, g_digitLimit );

    ArithModulus *pMod;

    // Get an odd modulus
    UINT32 nFail = 0;
    do {
        pMod = randomArithModulus( nD, nFail );
        nFail++;
    } while( (SymCryptIntGetValueLsbits32( pMod->m_pScInt ) & 1 ) == 0 );

    ArithModElement *pSrc = randomArithModElement( pMod );
    ArithModElement *pDst  = randomArithModElement( pMod );
    UINT32 exp;
    UINT32 i;
    UINT32 c;

    pDst->checkValue();
    // Pick an exponent, heavilly weighted to small values
    exp = 1;
    while( exp < 128 && (g_rng.byte() & 1) == 0 )
    {
        exp++;
    }

    SymCryptModDivPow2( pMod->m_pScModulus, pSrc->m_pScModElement, exp, pDst->m_pScModElement, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nD ) );
    SymCryptIntCopy( pSrc->m_pScInt, pDst->m_pScInt );              // Int = Src
    SymCryptIntDivPow2( pMod->m_pScInt, 1, pDst->m_pScTmp1 );       // Tmp1 = mod div 2
    SymCryptIntAddUint32( pDst->m_pScTmp1, 1, pDst->m_pScTmp1 );    // Tmp = (mod div 2) + 1

    for( i=0; i<exp; i++ )
    {
        c = SymCryptIntGetValueLsbits32( pDst->m_pScInt ) & 1;
        SymCryptIntDivPow2( pDst->m_pScInt, 1, pDst->m_pScInt );
        if( c != 0 )
        {
            SymCryptIntAddSameSize( pDst->m_pScInt, pDst->m_pScTmp1, pDst->m_pScInt );  // Int += Mod div 2 + 1
        }
    }

    TEST_CHECK_VALUE( pDst );
}

VOID
testModNeg()
{
    SIZE_T nD = g_rng.sizet( 1, g_digitLimit );

    ArithModulus *pMod = randomArithModulus( nD );
    ArithModElement *pDst = randomArithModElement( pMod );

    pDst->checkValue();

    SymCryptModNeg( pMod->m_pScModulus, pDst->m_pScModElement, pDst->m_pScModElement, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nD ) );

    SymCryptIntSubSameSize( pMod->m_pScInt, pDst->m_pScInt, pDst->m_pScInt );

    // Reduce to handle the case of input == 0
    SymCryptIntDivMod( pDst->m_pScInt, pMod->m_pScDivisor, NULL, pDst->m_pScInt, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nD ) );

    TEST_CHECK_VALUE( pDst );
}

UINT32 modIsEqual = 0;
UINT32 modIsNotEqual = 0;

VOID
testModIsEqual()
{
    SIZE_T nD = g_rng.sizet( 1, g_digitLimit );

    ArithModulus *pMod = randomArithModulus( nD );

    ArithModElement *pSrc1 = randomArithModElement( pMod );
    ArithModElement *pSrc2 = randomArithModElement( pMod );

    UINT32 eqMod, eqInt;

    eqMod = SymCryptModElementIsEqual( pMod->m_pScModulus, pSrc1->m_pScModElement, pSrc2->m_pScModElement );
    eqInt = SymCryptIntIsEqual( pSrc1->m_pScInt, pSrc2->m_pScInt );

    if( eqInt )
    {
        modIsEqual++;
    } else {
        modIsNotEqual++;
    }

    CHECK( eqMod == eqInt, "ModElementIsEqual doesn't agree with IntIsEqual" );
}

VOID
testModInv()
{
    SIZE_T nD;
    UINT32 nFail;
    ArithModulus *pMod;
    ArithModElement *pSrc;
    ArithModElement *pDst;
    SYMCRYPT_ERROR scError;

    // Pick a random digit size that allows primes
    do {
        nD =  g_rng.sizet( 1, g_digitLimit );
    } while( !isPrimePossible( (UINT32) nD ) );

    // Pick a prime modulus
    nFail = 0;
    do {
        pMod = randomArithModulus( nD, nFail );
        nFail++;
    } while( (pMod->m_flags & SYMCRYPT_FLAG_MODULUS_PRIME ) == 0 );

    // pick a nonzero element to invert.
    nFail = 0;
    do {
        pSrc = randomArithModElement( pMod, nFail );
        nFail++;
    } while( SymCryptIntIsEqualUint32( pSrc->m_pScInt, 0 ) != 0 );

    pDst = randomArithModElement( pMod );

    pDst->checkValue();

    // Pass a random value for the source_public flag
    scError = SymCryptModInv( pMod->m_pScModulus,
                                pSrc->m_pScModElement,
                                pDst->m_pScModElement,
                                (0 - (g_rng.byte() & 1)) & SYMCRYPT_FLAG_DATA_PUBLIC,
                                g_scratch,
                                SYMCRYPT_SCRATCH_BYTES_FOR_MODINV( nD ) );
    CHECK( scError == SYMCRYPT_NO_ERROR, "Modular inverse error" );

    // Be careful in computing the result. We can only use Dst->Tmp1, and Dst->Tmp2 because pSrc == pDst is allowed.
    SymCryptModElementToInt( pMod->m_pScModulus, pDst->m_pScModElement, pDst->m_pScTmp1, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nD ) );
    SymCryptIntMulSameSize( pSrc->m_pScInt, pDst->m_pScTmp1, pDst->m_pScTmp2, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nD ) );
    SymCryptIntDivMod( pDst->m_pScTmp2, pMod->m_pScDivisor, pDst->m_pScTmp2, pDst->m_pScTmp1, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nD ) );

    CHECK( SymCryptIntIsEqualUint32( pDst->m_pScTmp1, 1 ), "ModInv returned wrong answer" );

    // Fetch the result value again, this time into the pScInt value which we couldn't use earlier because of the pSrc == pDst case.
    SymCryptModElementToInt( pMod->m_pScModulus, pDst->m_pScModElement, pDst->m_pScInt, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nD ) );

    TEST_CHECK_VALUE( pDst );
}

VOID
testModSetRandom()
{
    SYMCRYPT_ERROR scError;

    BYTE r = 0;             // Byte to get various probabilities

    UINT32 nBytes = 0;
    SIZE_T nDigits = 0;

    ArithModulus *pMod = NULL;
    ArithModElement *pSrc = NULL;

    UINT32 flags = 0;               // Flags for the SymCryptModSetRandom

    // Pick a random modulus
    nDigits = g_rng.sizet( 1, g_digitLimit );
    pMod = randomArithModulus( nDigits );

    //
    // Pick proper flags out of 8 possible combinations
    //  N: Not allowed, A: Allowed
    //    #  Zero    One     MinusOne
    //    0   A       A       A
    //    1   A       A       N
    //    2   A       N       A     <-- here allow Zero implies allow One
    //    3   A       N       N     <-- here allow Zero implies allow One
    //    4   N       A       A
    //    5   N       A       N
    //    6   N       N       A
    //    7   N       N       N
    //

    // Pick one of the valid combinations uniformly at random
    r = g_rng.byte() & 0x07;

    // Set the flags accordingly
    if ((r&4)==0)   { flags |= SYMCRYPT_FLAG_MODRANDOM_ALLOW_ZERO; }
    if ((r&2)==0)   { flags |= SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE; }
    if ((r&1)==0)   { flags |= SYMCRYPT_FLAG_MODRANDOM_ALLOW_MINUSONE; }

    //
    // Picking the random element
    //

    nBytes = pMod->m_nDigits * (UINT32)g_bytesPerDigit;
    pSrc = randomArithModElement( pMod );

    SymCryptModSetRandom(
                    pMod->m_pScModulus,
                    pSrc->m_pScModElement,
                    flags,
                    g_scratch,
                    SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ) );

    scError = SymCryptModElementGetValue(
                    pMod->m_pScModulus,
                    pSrc->m_pScModElement,
                    g_scratch,
                    nBytes,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    &g_scratch[nBytes],
                    SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nDigits ) );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    scError = SymCryptIntSetValue(
                    g_scratch,
                    nBytes,
                    SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
                    pSrc->m_pScInt );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    TEST_CHECK_VALUE( pSrc );
}

VOID
testModExp()
{
    UINT32 nFail;

    UINT32 nD;
    UINT32 nDI;

    ArithModulus *pMod;

    ArithModElement *pB1;

    ArithInt *pE1;
    ArithInt *pE2;

    PSYMCRYPT_MODELEMENT peTmp1 = NULL;
    PSYMCRYPT_MODELEMENT peTmp2 = NULL;
    UINT32 cbModElement = 0;

    PSYMCRYPT_INT piTmp = NULL;
    UINT32 cbInt = 0;

    PBYTE pbScratch = g_scratch;

    BYTE rand = g_rng.byte() & 0x03;

    UINT32 flags = ((g_rng.byte() & 0x01) == 0) ? 0 : SYMCRYPT_FLAG_DATA_PUBLIC;

    // This test verifies that the following exponents' properties
    // hold for random values. These properties imply the most general
    // recursive definition of exponentiation in abstract algebra, i.e.
    // x^1 = x and x^(n+1) = x * x^n. Also they imply that x^0 = 1
    // for any x!=0.
    //
    // With probability 25% (when rand==0) if ( b1^1 == b1 )
    // With probability 75% (when rand!=0) if ( b1^e1*b1^e2 == b1^(e1+e2) )     * This is also satisfied when 0^0 = 1
    //

    // Pick a random digit size for the exponents
    // piTmp will have nDI + 1 digits so that we don't overflow
    nDI =  (UINT32)g_rng.sizet( 1, g_digitLimit-1 );

    // Pick a random digit size for the modulus and a modulus bigger than 1
    nD =  (UINT32)g_rng.sizet( 1, g_digitLimit );
    nFail = 0;
    do
    {
        pMod = randomArithModulus( nD, nFail++ );
    } while (SymCryptIntBitsizeOfValue( SymCryptIntFromModulus( pMod->m_pScModulus)) <= 1);

    // Pick b1
    pB1 = randomArithModElement( pMod );

    // Pick e1 and e2
    pE1 = randomArithInt( nDI );
    pE2 = randomArithInt( nDI );

    // Create temporary elements in the g_scratch space
    cbModElement = SymCryptSizeofModElementFromModulus( pMod->m_pScModulus );
    peTmp1 = SymCryptModElementCreate( pbScratch, cbModElement, pMod->m_pScModulus );
    pbScratch += cbModElement;
    peTmp2 = SymCryptModElementCreate( pbScratch, cbModElement, pMod->m_pScModulus );
    pbScratch += cbModElement;

    cbInt = SymCryptSizeofIntFromDigits( nDI + 1 ); // Add one digit so we never overflow
    piTmp = SymCryptIntCreate( pbScratch, cbInt, nDI + 1 );
    pbScratch += cbInt;

    if (rand == 0)
    {
        // Set piTmp to 1
        SymCryptIntSetValueUint32( 1, piTmp );

        // b1^1 -> Tmp1
        SymCryptModExp(
            pMod->m_pScModulus,
            pB1->m_pScModElement,
            piTmp,
            1,
            flags,
            peTmp1,
            pbScratch,
            SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP( nD ) );

        // b1 -> Tmp2
        SymCryptModElementCopy( pMod->m_pScModulus, pB1->m_pScModElement, peTmp2 );
    }
    else
    {

        // b1^e1 -> Tmp1
        SymCryptModExp(
                pMod->m_pScModulus,
                pB1->m_pScModElement,
                pE1->m_pScInt,
                SYMCRYPT_MAX(1, SymCryptIntBitsizeOfValue(pE1->m_pScInt)),
                flags,
                peTmp1,
                pbScratch,
                SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP( nD ) );

        // b1^e2 -> Tmp2
        SymCryptModExp(
            pMod->m_pScModulus,
            pB1->m_pScModElement,
            pE2->m_pScInt,
            SYMCRYPT_MAX(1, SymCryptIntBitsizeOfValue(pE2->m_pScInt)),
            flags,
            peTmp2,
            pbScratch,
            SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP( nD ) );

        // Add e2 and e1
        SymCryptIntAddMixedSize( pE1->m_pScInt, pE2->m_pScInt, piTmp );

        // b1^e1*b1^e2 -> Tmp1
        SymCryptModMul( pMod->m_pScModulus, peTmp1, peTmp2, peTmp1, pbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nD ) );

        // b1^(e1+e2) -> Tmp2
        SymCryptModExp(
            pMod->m_pScModulus,
            pB1->m_pScModElement,
            piTmp,
            SYMCRYPT_MAX(1, SymCryptIntBitsizeOfValue(piTmp)),
            flags,
            peTmp2,
            pbScratch,
            SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP( nD ) );
    }

    CHECK3( SymCryptModElementIsEqual( pMod->m_pScModulus, peTmp1, peTmp2 ), "testModExp %x property mismatch", rand);
}

VOID
testModMultiExp()
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    UINT32 nFail;

    UINT32 nD;
    UINT32 nDI;

    ArithModulus *pMod;

    ArithModElement *pBase;
    ArithInt *pExp;

    PCSYMCRYPT_MODELEMENT peBases[SYMCRYPT_MODMULTIEXP_MAX_NBASES] = { 0 };
    PCSYMCRYPT_INT piExps[SYMCRYPT_MODMULTIEXP_MAX_NBASES] = { 0 };
    UINT32 nBitsExps[SYMCRYPT_MODMULTIEXP_MAX_NBASES] = { 0 };
    UINT32 nBitsExpMax = 1;

    PSYMCRYPT_MODULUS pmMod = NULL;
    PSYMCRYPT_MODELEMENT peTmp1 = NULL;
    PSYMCRYPT_MODELEMENT peTmp2 = NULL;
    UINT32 cbModElement = 0;

    PBYTE pbScratch = g_scratch;

    // Pick random flags and number of bases
    UINT32 flags = ((g_rng.byte() & 0x01) == 0) ? 0 : SYMCRYPT_FLAG_DATA_PUBLIC;
    UINT32 nBases = (g_rng.byte() & (SYMCRYPT_MODMULTIEXP_MAX_NBASES - 1)) + 1;        // This only works when SYMCRYPT_MODMULTIEXP_MAX_NBASES is a power of 2

    // Pick a random digit size for the exponents
    nDI =  (UINT32)g_rng.sizet( 1, g_digitLimit );

    // Pick a random digit size for the modulus and a modulus bigger than 1
    nD =  (UINT32)g_rng.sizet( 1, g_digitLimit );
    nFail = 0;
    do
    {
        pMod = randomArithModulus( nD, nFail++ );
        pmMod = pMod->m_pScModulus;
    } while (SymCryptIntBitsizeOfValue( SymCryptIntFromModulus( pmMod )) <= 1);

    // Pick bases and exponents and set the pointers
    for (UINT32 i=0; i<nBases; i++)
    {
        pBase = randomArithModElement( pMod );
        peBases[i] = pBase->m_pScModElement;

        pExp = randomArithInt( nDI );
        piExps[i] = pExp->m_pScInt;

        nBitsExps[i] = SYMCRYPT_MAX( 1, SymCryptIntBitsizeOfValue(piExps[i]));       // We can never pass nBitsExp == 0
        nBitsExpMax = SYMCRYPT_MAX( nBitsExpMax, nBitsExps[i] );
    }

    // Create temporary elements in the g_scratch space
    cbModElement = SymCryptSizeofModElementFromModulus( pmMod );
    peTmp1 = SymCryptModElementCreate( pbScratch, cbModElement, pmMod );
    pbScratch += cbModElement;
    peTmp2 = SymCryptModElementCreate( pbScratch, cbModElement, pmMod );
    pbScratch += cbModElement;

    // First calculate the result using ModExp
    SymCryptModElementSetValueUint32( 1, pmMod, peTmp1, pbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nD ) );

    for (UINT32 i=0; i<nBases; i++)
    {
        SymCryptModExp( pmMod, peBases[i], piExps[i], nBitsExps[i], flags, peTmp2, pbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_MODEXP( nD ) );

        SymCryptModMul( pmMod, peTmp1, peTmp2, peTmp1, pbScratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( nD ) );
    }


    // MultiExp
    scError = SymCryptModMultiExp(
            pmMod,
            peBases,
            piExps,
            nBases,
            nBitsExpMax,
            flags,
            peTmp2,         // Set it into Tmp2
            pbScratch,
            SYMCRYPT_SCRATCH_BYTES_FOR_MODMULTIEXP( nD, nBases, nBitsExpMax ) );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SymCryptModMultiExp failure");

    CHECK( SymCryptModElementIsEqual( pMod->m_pScModulus, peTmp1, peTmp2 ), "testModMultiExp mismatch");
}

//==================================================================
// Trial division tests

PCSYMCRYPT_TRIALDIVISION_CONTEXT g_trialDivisionContexts[100] = {0};

UINT32 g_smallPrimes[100000];
UINT32 g_nSmallPrimes;

VOID
generateSmallPrimes()
{
    g_smallPrimes[0] = 2;
    g_smallPrimes[1] = 3;

    UINT32 nPrimes = 2;

    UINT32 n = 3;

    while( nPrimes < ARRAY_SIZE( g_smallPrimes ) )
    {
        n += 2; // next candidate
        for( UINT32 i=1; i<=nPrimes; i++ )
        {
            UINT32 p = g_smallPrimes[i];
            if( p*p > n )
            {
                // found a prime!
                g_smallPrimes[nPrimes++] = n;
                break;
            }
            if( n % p == 0 )
            {
                // found a composite
                break;
            }
        }
    }

    g_nSmallPrimes = nPrimes;
}

VOID
testTrialDivisionInit()
{
    generateSmallPrimes();
}

VOID
testTrialDivisionCleanup()
{
    print( "Trial division limits:\n" );
    for( UINT32 i=0; i<ARRAY_SIZE( g_trialDivisionContexts ); i++ )
    {
        if( g_trialDivisionContexts[i] != NULL )
        {
            print( "    %d -> %d\n", i, SymCryptTestTrialdivisionMaxSmallPrime( g_trialDivisionContexts[i] ) );
            SymCryptFreeTrialDivisionContext( g_trialDivisionContexts[i] );
            g_trialDivisionContexts[i] = NULL;
        }
    }
}

VOID
testTrialDivision()
{
    SIZE_T      nD = g_rng.sizet( 1, g_digitLimit );
    ArithInt    *pSrc = randomArithInt( nD );

    if( g_trialDivisionContexts[nD] == NULL )
    {
        g_trialDivisionContexts[nD] = SymCryptCreateTrialDivisionContext( (UINT32) nD );
        CHECK( g_trialDivisionContexts[nD] != NULL, "Out of memory" );
        //print( "Trial division maxprime[%d]=%d\n", nD, SymCryptTestTrialdivisionMaxSmallPrime( g_trialDivisionContexts[nD] ) );
    }

    if( g_trialDivisionContexts[nD+1] == NULL )
    {
        g_trialDivisionContexts[nD+1] = SymCryptCreateTrialDivisionContext( (UINT32)nD+1 );
        CHECK( g_trialDivisionContexts[nD+1] != NULL, "Out of memory" );
        //print( "Trial division maxprime[%d]=%d\n", nD+1, SymCryptTestTrialdivisionMaxSmallPrime( g_trialDivisionContexts[nD+1] ) );
    }

    UINT32 div = SymCryptIntFindSmallDivisor( g_trialDivisionContexts[nD], pSrc->m_pScInt, NULL, 0 );

    PSYMCRYPT_INT piTmp = SymCryptIntAllocate( (UINT32) nD + 1 );
    SymCryptIntCopyMixedSize( pSrc->m_pScInt, piTmp );

    if( div == 0 )
    {
        // Check with one more digit which does more trial division. Simplifies later test as well.
        div = SymCryptIntFindSmallDivisor( g_trialDivisionContexts[nD+1], pSrc->m_pScInt, NULL, 0 );
        CHECK( div == 0 || div > SymCryptTestTrialdivisionMaxSmallPrime( g_trialDivisionContexts[nD] ), "Divisor inconsistent" );
    }

    if( div != 0 )
    {
        PSYMCRYPT_DIVISOR pdDiv = SymCryptDivisorAllocate( 1 );
        PSYMCRYPT_INT piRem = SymCryptIntAllocate( 1 );

        // We have a divisor; check that it is real
        SymCryptIntSetValueUint32( div, SymCryptIntFromDivisor( pdDiv ) );
        SymCryptIntToDivisor( SymCryptIntFromDivisor( pdDiv ), pdDiv, 1, 0, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_DIVISOR( 1 ) );

        SymCryptIntDivMod( pSrc->m_pScInt, pdDiv, NULL, piRem, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD( nD, 1 ));

        CHECK4( SymCryptIntIsEqualUint32( piRem, 0 ), "Trial division divisor %d doesn't divide %d-bit number", div, SymCryptIntBitsizeOfValue( pSrc->m_pScInt ) );

        SymCryptIntFree( piRem );
        piRem = NULL;
        SymCryptDivisorFree( pdDiv );
        pdDiv = NULL;
    } else {
        // Pick a random prime that should be found
        UINT32 maxPrime = SymCryptTestTrialdivisionMaxSmallPrime( g_trialDivisionContexts[nD+1] );
        SYMCRYPT_ASSERT( maxPrime <= g_smallPrimes[ ARRAY_SIZE( g_smallPrimes ) - 1] );

        SIZE_T nP = ARRAY_SIZE( g_smallPrimes );
        for(;;)
        {
            SIZE_T i = g_rng.sizet( nP );
            div = g_smallPrimes[i];
            if( div <= maxPrime )
            {
                break;
            }
            nP = i;
        }

        SymCryptIntMulUint32( piTmp, div, piTmp );       // Requires src & dst to be same size, hence the copy before it.

        UINT32 t = SymCryptIntFindSmallDivisor( g_trialDivisionContexts[nD + 1], piTmp, NULL, 0 );
        CHECK3( div == t, "Trial division did not find factor %d", div );
    }
    SymCryptIntFree( piTmp );
}


//==================================================
// Simple test functions used for debuggins
//

VOID
testDivisor( PBYTE pbDiv, UINT32 cbDiv )
{
    PSYMCRYPT_INT       pNum;
    PSYMCRYPT_INT       pDivInt;
    PSYMCRYPT_DIVISOR   pDiv;
    PSYMCRYPT_INT       pQuotient;
    PSYMCRYPT_INT       pRemainder;
    PSYMCRYPT_INT       pTmp;

    BYTE    num[16];
    UINT32  c;

    UINT32  i,j;

    SYMCRYPT_ERROR  scError;

    UINT32  nDigits = SymCryptDigitsFromBits( 8 * 16 );

    pNum = SymCryptIntAllocate( nDigits );
    pDivInt = SymCryptIntAllocate( nDigits );
    pDiv = SymCryptDivisorAllocate( nDigits );
    pQuotient = SymCryptIntAllocate( nDigits );
    pRemainder = SymCryptIntAllocate( nDigits );
    pTmp = SymCryptIntAllocate( 2 * nDigits );

    CHECK( cbDiv > 0 && cbDiv <= 16, "?" );

    scError = SymCryptIntSetValue( pbDiv, cbDiv, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, pDivInt );
    CHECK( scError == SYMCRYPT_NO_ERROR, "SetValue error on divisor" );

    SymCryptIntToDivisor( pDivInt, pDiv, 0, 0, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_DIVISOR( nDigits ) );

    for( i=cbDiv; i<16; i++ )
    {
        for( j=0; j<i; j++ )
        {
            num[j] = g_rng.byte();
        }

        scError = SymCryptIntSetValue( &num[0], i, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, pNum );
        CHECK( scError == SYMCRYPT_NO_ERROR, "SetValue error on Numerator" );

        SymCryptIntDivMod( pNum, pDiv, pQuotient, pRemainder, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD( 2*nDigits, nDigits ) );

        SymCryptIntMulSameSize( pQuotient, pDivInt, pTmp, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_INT_MUL( 2*nDigits ) );
        c = SymCryptIntAddMixedSize( pTmp, pRemainder, pTmp );
        CHECK( c == 0, "?" );
        c = SymCryptIntIsEqual( pTmp, pNum );
        CHECK( c != 0, "DivMod verification failed" );
    }

    SymCryptIntFree( pNum );
    SymCryptIntFree( pDivInt );
    SymCryptDivisorFree( pDiv );
    SymCryptIntFree( pQuotient );
    SymCryptIntFree( pRemainder );
    SymCryptIntFree( pTmp );
}

VOID
debugtestDiv()
{
    BYTE    div[16];

    UINT32 i,j,k;

    // i = # bytes in divisor to test
    for( i=1; i<16; i++ )
    {
        // j = leading byte, skip the 0 value
        for( j=1; j<256; j++ )
        {
            k = i-1;
            div[k]= (BYTE) j;

            while( k > 0 )
            {
                k--;
                div[k] = g_rng.byte();
            }
            testDivisor( &div[0], i );
        }
    }
}

VOID
debugtestModInv()
{
    PSYMCRYPT_MODULUS pMod;
    PSYMCRYPT_MODELEMENT pEl;

    pMod = SymCryptModulusAllocate( 1 );
    SymCryptIntSetValueUint32( 7, SymCryptIntFromModulus( pMod ) );
    SymCryptIntToModulus( SymCryptIntFromModulus( pMod ), pMod, 1000, SYMCRYPT_FLAG_DATA_PUBLIC | SYMCRYPT_FLAG_MODULUS_PRIME, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_MODULUS( 1 ) );

    pEl = SymCryptModElementAllocate( pMod );
    SymCryptModElementSetValueUint32( 3, pMod, pEl, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_MOD_OPERATIONS( 1 ) );

    CHECK( SymCryptModInv( pMod, pEl, pEl, 0, g_scratch, SYMCRYPT_SCRATCH_BYTES_FOR_MODINV( 1 ) ) == SYMCRYPT_NO_ERROR, "?" );

    SymCryptModElementFree( pMod, pEl );
    SymCryptModulusFree( pMod );
}

VOID
debugtestPrimeGeneration()
{
    SYMCRYPT_ERROR  scError = SYMCRYPT_NO_ERROR;
    UINT32          nD = 0;
    UINT32          nBytes = 0;
    UINT32          nBytesR = 0;

    BYTE            buf[MAX_INT_BYTES] = {0};

    PSYMCRYPT_INT   piDst = NULL;
    PSYMCRYPT_INT   piLow = NULL;
    PSYMCRYPT_INT   piHigh = NULL;
    UINT32          cbDst = 0;

    PBYTE           pbScratch = NULL;
    UINT32          cbScratch = 0;
    PBYTE           pbTmp = NULL;

    // Pick number of digits (max 3 so that we can print the numbers)
    nD = (UINT32)g_rng.sizet( 1, 4 );

    // Allocate the integers and the scratch space
    cbDst = SymCryptSizeofIntFromDigits( nD );
    cbScratch = 3*cbDst + SYMCRYPT_SCRATCH_BYTES_FOR_INT_PRIME_GEN(nD);
    pbScratch = (PBYTE)SymCryptCallbackAlloc( cbScratch );
    CHECK( pbScratch != NULL, "?" );

    pbTmp = pbScratch;

    // Create integers
    piDst = SymCryptIntCreate( pbTmp, cbDst, nD );
    CHECK( piDst != NULL, "?" );
    pbTmp += cbDst;
    piLow = SymCryptIntCreate( pbTmp, cbDst, nD );
    CHECK( piLow != NULL, "?" );
    pbTmp += cbDst;
    piHigh = SymCryptIntCreate( pbTmp, cbDst, nD );
    CHECK( piHigh != NULL, "?" );
    pbTmp += cbDst;

    nBytes = (SymCryptIntBitsizeOfObject(piDst)+7) / 8;

    // Set a random low limit
    nBytesR = (UINT32)g_rng.sizet(1, nBytes);
    SymCryptCallbackRandom( buf, nBytesR );
    scError = SymCryptIntSetValue( buf, nBytesR, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piLow );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );

    // Set a random high limit
    do
    {
        nBytesR = (UINT32)g_rng.sizet(1, nBytes);
        SymCryptCallbackRandom( buf, nBytesR );
        scError = SymCryptIntSetValue( buf, nBytesR, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piHigh );
        CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    } while (SymCryptIntIsLessThan( piHigh, piLow ));

    // Print Numbers
    scError = SymCryptIntGetValue( piLow, buf, nBytes, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    iprint("\nLow  : ");
    for (UINT32 i=0; i<nBytes; i++)
    {
        iprint("%02X", buf[i]);
    }
    scError = SymCryptIntGetValue( piHigh, buf, nBytes, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    iprint("\nHigh : ");
    for (UINT32 i=0; i<nBytes; i++)
    {
        iprint("%02X", buf[i]);
    }

    // Generate a prime
    UINT32 maxTries = 100 * SymCryptIntBitsizeOfValue( piHigh );
    scError = SymCryptIntGenerateRandomPrime( piLow, piHigh, NULL, 0, maxTries, 0, piDst, pbTmp, SYMCRYPT_SCRATCH_BYTES_FOR_INT_PRIME_GEN(nD));
    CHECK3( scError == SYMCRYPT_NO_ERROR, "Error prime generation: %x", scError );

    // Print the result
    scError = SymCryptIntGetValue( piDst, buf, nBytes, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST );
    CHECK( scError == SYMCRYPT_NO_ERROR, "?" );
    iprint("\nPrime: ");
    for (UINT32 i=0; i<nBytes; i++)
    {
        iprint("%02X", buf[i]);
    }

    SymCryptWipe(pbScratch,cbScratch);
    SymCryptCallbackFree(pbScratch);
}

UINT32 GcdUint32( UINT32 a, UINT32 b )
{
    UINT32 t;

    while( a != 0 )
    {
        t = b % a;  // GCD( a, b ) == GCD( a, t )

        // Move the bigger term into b, the smaller into a
        b = a;
        a = t;
    }

    return b;
}

VOID testCompositeModInv()
{
    // We just check that ModInv works properly with weird inputs
    PSYMCRYPT_MODULUS pMod = SymCryptModulusAllocate( 1 );
    PSYMCRYPT_MODELEMENT pEl = SymCryptModElementAllocate( pMod );
    PSYMCRYPT_MODELEMENT pInv = SymCryptModElementAllocate( pMod );
    SIZE_T cbScratch = 1 << 20;
    PBYTE pbScratch = (PBYTE) SymCryptCallbackAlloc( cbScratch );   // this allocator provides the necessary alignment
    SYMCRYPT_ERROR scError;

    CHECK( pMod != NULL && pEl != NULL && pbScratch != NULL, "Out of memory" );

    for( int cnt = 0; cnt < 1000; cnt++ )
    {
        UINT32 mod = (UINT32) g_rng.sizet( 2, (1<<16) );

        // Must be 2 or odd to even pass the sanity checks for prime moduli
        if( mod != 2 )
        {
            mod |= 1;
        }

        UINT32 x = (UINT32) g_rng.sizet( mod );
        CHECK( x < mod, "?" );
        SymCryptIntSetValueUint32( mod, SymCryptIntFromModulus( pMod ) );

        // Our current code requires the PRIME and DATA_PUBLIC flags.

        UINT32 modFlags = 0;
        BYTE b = g_rng.byte();

        /* Code to generat random flags (for when we support them)
        if( b & 1 )
        {
            if( b & 2 )
            {
                modFlags |= SYMCRYPT_FLAG_DATA_PUBLIC;
            } else {
                modFlags |= SYMCRYPT_FLAG_MODULUS_PARITY_PUBLIC;
            }
        }
        if( (b & 4) != 0 && (mod == 2 || (mod &  1) != 0 )  )
        {
            // We deliberately limit ourselves to only checking for oddness in primes
            // as our RSA/DSA code doesn't check for primality when receiving parameters from
            // outside parties.
            modFlags |= SYMCRYPT_FLAG_MODULUS_PRIME;
        }
        */
        modFlags = SYMCRYPT_FLAG_DATA_PUBLIC | SYMCRYPT_FLAG_MODULUS_PRIME;

        SymCryptIntToModulus( SymCryptIntFromModulus( pMod ), pMod, g_rng.byte(), modFlags, pbScratch, cbScratch );

        SymCryptModElementSetValueUint32( x, pMod, pEl, pbScratch, cbScratch );

        // We must use DATA_PUBLIC, otherwise the modinv routine blinds the input which
        // can introduce errors when the modulus isn't prime, and that makes our test
        // less sensitive.
        UINT32 opFlags = SYMCRYPT_FLAG_DATA_PUBLIC;

        scError = SymCryptModInv( pMod, pEl, pInv, opFlags, pbScratch, cbScratch );

        // Check that the result is correct when we get no error
        if( scError == SYMCRYPT_NO_ERROR )
        {
            SymCryptModMul( pMod, pEl, pInv, pInv, pbScratch, cbScratch );
            SYMCRYPT_ERROR scError2 = SymCryptModElementGetValue( pMod, pInv, &b, 1, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, pbScratch, cbScratch );
            CHECK( scError2 == SYMCRYPT_NO_ERROR && b == 1, "ModInv * input is not 1" );
        }

        BOOL coPrime = GcdUint32( x, mod ) == 1;

        CHECK( coPrime || scError != SYMCRYPT_NO_ERROR, "No error for modinv that does not exist" );

        CHECK( (modFlags & SYMCRYPT_FLAG_DATA_PUBLIC) == 0 ||
                (modFlags & SYMCRYPT_FLAG_MODULUS_PRIME) == 0 ||
                !coPrime ||
                scError == SYMCRYPT_NO_ERROR, "Unexpected error for modinverse" );
    }

    SymCryptWipe(pbScratch,cbScratch);
    SymCryptCallbackFree(pbScratch);
    SymCryptModElementFree( pMod, pEl );
    SymCryptModElementFree( pMod, pInv );
    SymCryptModulusFree( pMod );
}


VOID
testArithmetic()
{
    UINT32 w;
    UINT32 i;
    BOOLEAN reject;

    static BOOL hasRun = FALSE;

    if( hasRun )
    {
        return;
    }
    hasRun = TRUE;

    // Skip if there is no Int* or Mod* algorithm to test.
    if( !isAlgorithmPresent( "Int", TRUE ) && !isAlgorithmPresent( "Mod", TRUE ) )
    {
        return;
    }

    iprint( "    Arithmetic" );

    //
    // Set a woop modulus.
    // We pick a random 32-bit value and reject any with a factor < 256
    // that avoids very smooth moduli. The max # prime factors is 3.
    // It must also be odd to make division by 2 mod woopMod easier.
    //
    do
    {
        w = g_rng.uint32() | (1UL << 31) | 1;

        reject = FALSE;
        for( i=3; i<256; i += 2 )   // We already made it odd, so no need to test i=2
        {
            if( w % i == 0 )
            {
                reject = TRUE;
                break;
            }
        }
    } while( reject );

    g_woopMod = w;
    g_digitLimit = SymCryptDigitsFromBits( MAX_INT_BITS ) + 1;

    //
    // At this point, the test infrastructure has been set up
    //

    INT64 nOutstandingAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nOutstandingCheckedAllocs);
    CHECK3( nOutstandingAllocs == 0, "Memory leak %d", nOutstandingAllocs );

    //debugtestDiv();
    //debugtestModInv();
    //debugtestPrimeGeneration();

    testDigitsFromBits();
    setupCarryWoops();

    rnddRegisterInitFunction( initIntObjects );
    rnddRegisterInitFunction( initDivisorObjects );
    rnddRegisterInitFunction( initModulusObjects );
    rnddRegisterInitFunction( initModElementObjects );

    rnddRegisterCleanupFunction( cleanupIntObjects );
    rnddRegisterCleanupFunction( cleanupDivisorObjects );
    rnddRegisterCleanupFunction( cleanupModulusObjects );
    rnddRegisterCleanupFunction( cleanupModElementObjects );

    rnddRegisterTestFunction( testIntObjectLifetime, "IntObjectLifetime", 5 );
    rnddRegisterTestFunction( testIntCopy, "IntCopy", 1 );
    rnddRegisterTestFunction( testIntBitsizeOfValue, "IntBitsizeOfValue", 10 );
    rnddRegisterTestFunction( testIntCopyMixedSize, "IntCopyMixedSize", 10 );
    rnddRegisterTestFunction( testIntSetValue, "IntSetValue", 20 );             // More frequent to generate corner-case values
    rnddRegisterTestFunction( testIntSetValueUint32, "IntSetValueUint32", 10 );
    rnddRegisterTestFunction( testIntGetValue, "IntGetValue", 10 );
    rnddRegisterTestFunction( testIntGetValueLsbits, "IntGetValueLsbits", 5 );
    rnddRegisterTestFunction( testIntAddUint32, "IntAddUint32", 10 );
    rnddRegisterTestFunction( testIntAddSameSize, "IntAddSameSize", 10 );
    rnddRegisterTestFunction( testIntAddMixedSize, "IntAddMixedSize", 10 );
    rnddRegisterTestFunction( testIntSubUint32, "IntSubUint32", 10 );
    rnddRegisterTestFunction( testIntSubSameSize, "IntSubSameSize", 10 );
    rnddRegisterTestFunction( testIntSubMixedSize, "IntSubMixedSize", 10 );
    rnddRegisterTestFunction( testIntNeg, "IntNeg", 3 );
    rnddRegisterTestFunction( testIntGetBits, "IntGetBits", 10 );
    rnddRegisterTestFunction( testIntSetBits, "IntSetBits", 10 );

    rnddRegisterTestFunction( testIntMulPow2, "IntMulPow2", 10 );
    rnddRegisterTestFunction( testIntModPow2, "IntModPow2", 10 );
    rnddRegisterTestFunction( testIntDivPow2, "IntDivPow2", 10 );

    rnddRegisterTestFunction( testIsEqualUint32,    "IntIsEqualUint32", 5 );
    rnddRegisterTestFunction( testIsEqual,          "IntIsEqual",       5 );
    rnddRegisterTestFunction( testIsLessThan,       "IntIsLessThan",    5 );

    rnddRegisterTestFunction( testIntMulUint32,     "IntMulUint32", 10 );
    rnddRegisterTestFunction( testIntMulSameSize,   "IntMulSameSize", 10 );
    rnddRegisterTestFunction( testIntMulMixedSize,  "IntMulMixedSize", 10 );
    rnddRegisterTestFunction( testIntSquare,        "IntSquare", 10 );

    rnddRegisterTestFunction( testDivisorObjectLifetime, "DivisorObjectLifetime", 5 );
    rnddRegisterTestFunction( testDivisorCopy, "DivisorCopy", 1 );
    rnddRegisterTestFunction( testIntDivMod,        "IntDivMod", 10 );
    rnddRegisterTestFunction( testIntGcdEx,         "IntGcdEx", 1 );

    rnddRegisterTestFunction( testIntPrimalityTest, "IntPrimalityTest", 1 );    // very expensive

    rnddRegisterTestFunction( testModulusObjectLifetime, "ModulusObjectLifetime", 5 );
    rnddRegisterTestFunction( testModulusCopy, "ModulusCopy", 1 );

    rnddRegisterTestFunction( testModElementObjectLifetime, "ModElementObjectLifetime", 5 );
    rnddRegisterTestFunction( testModElementCopy, "ModElementCopy", 1 );
    rnddRegisterTestFunction( testModElementSetValue, "ModElementSetValue", 1 );
    rnddRegisterTestFunction( testModElementSetValueUint32, "ModElementSetValueUint32", 1 );
    rnddRegisterTestFunction( testModElementSetValueNegUint32, "ModElementSetValueNegUint32", 1 );

    rnddRegisterTestFunction( testModAdd, "ModAdd", 10 );
    rnddRegisterTestFunction( testModSub, "ModSub", 10 );
    rnddRegisterTestFunction( testModNeg, "ModNeg", 10 );
    rnddRegisterTestFunction( testModMul, "ModMul", 10 );
    rnddRegisterTestFunction( testModSquare, "ModSquare", 10 );
    rnddRegisterTestFunction( testModDivPow2, "ModDivPow2", 3 );
    rnddRegisterTestFunction( testModIsEqual, "ModIsEqual", 10 );
    rnddRegisterTestFunction( testModInv, "ModInv", 1 );        // very expensive
    rnddRegisterTestFunction( testModExp, "ModExp", 1 );        // very expensive
    rnddRegisterTestFunction( testModMultiExp, "ModMultiExp", 1 );        // very expensive
    rnddRegisterTestFunction( testModSetRandom, "ModSetRandom", 10 );

    rnddRegisterInitFunction( testTrialDivisionInit );
    rnddRegisterTestFunction( testTrialDivision, "TrialDivision", 5 );
    rnddRegisterCleanupFunction( testTrialDivisionCleanup );
/*
*/
    // The invariant functions are run after every test; only used during debugging.
    // rnddRegisterInvariantFunction( checkAllIntWoops );

    rnddRunTest( 5, 1 );

    nOutstandingAllocs = SYMCRYPT_INTERNAL_VOLATILE_READ64(&g_nOutstandingCheckedAllocs);
    CHECK3( nOutstandingAllocs == 0, "Memory leak, %d outstanding", nOutstandingAllocs );

    // iprint( "ModIsEqual globals: EQ = %x, NEQ = %x\n", modIsEqual, modIsNotEqual );


    testCompositeModInv();

    iprint( "\n" );
}
