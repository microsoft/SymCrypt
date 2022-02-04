//
// integrity.c
// FIPS 140-3 integrity verification implementation for ELF binaries
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//


#include "precomp.h"

// These placeholder vaulues must match the values in process_fips_module.py
#define PLACEHOLDER_VALUE 0x8BADF00D
#define PLACEHOLDER_ARRAY \
{\
    0x5B, 0x75, 0xBB, 0xE4, 0x9E, 0x18, 0x03, 0x55,\
    0x08, 0x4E, 0x3F, 0xE7, 0x60, 0x7E, 0x4F, 0x08,\
    0xAA, 0x77, 0x0F, 0x0B, 0xAB, 0xC6, 0x58, 0x5A,\
    0xA9, 0x9F, 0x83, 0x4B, 0xD0, 0x6E, 0x67, 0x05\
}

// The following variables use placeholder values which will be modified after compile time by our
// helper script. They need to be statically initialized to non-zero values so they are put in the
// .data segment rather than the .bss segment, as the latter's representation in the module on disk
// is not necessarily the same size as the values in memory at runtime.
//
// Because these values are modified after compile time, the scalar values must be read using
// SYMCRYPT_FORCE_READ64 or the compiler may inline the placeholder values, leading to incorrect
// results at runtime.

// Relative virtual address of the HMAC key. Used to calculate where the module starts in memory
// at runtime.
const Elf64_Addr SymCryptVolatileFipsHmacKeyRva = (Elf64_Addr) PLACEHOLDER_VALUE;

// Offset to the end of the FIPS module. Bytes after this offset are not considered part of our
// FIPS module and are not included in the HMAC digest.
const Elf64_Off SymCryptVolatileFipsBoundaryOffset = PLACEHOLDER_VALUE;

// Key used for HMAC.
const unsigned char SymCryptVolatileFipsHmacKey[32] = PLACEHOLDER_ARRAY;

// HMAC digest calculated by our post-processing script after calculation. The HMAC digest
// we calculate at runtime is compared to this digest.
unsigned char SymCryptVolatileFipsHmacDigest[SYMCRYPT_HMAC_SHA256_RESULT_SIZE] = PLACEHOLDER_ARRAY;

typedef struct
{
    Elf64_Rela* rela;
    size_t relaEntryCount;
    Elf64_Rela* pltRela;
    size_t pltRelaEntryCount;
} Elf64_Rela_Info;

void SymCryptModuleUndoRelocation(
    _In_ const Elf64_Addr module_base,
    _Inout_ Elf64_Xword* const target,
    _In_ const Elf64_Rela* rela )
{
    Elf64_Xword replacement = 0;

    switch( ELF64_R_TYPE( rela->r_info ) )
    {
        case R_X86_64_RELATIVE:
        case R_AARCH64_RELATIVE:
            replacement = *target - (Elf64_Off) module_base;
            break;
        case R_X86_64_64:
        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
        case R_AARCH64_GLOB_DAT:
        case R_AARCH64_JUMP_SLOT:
            // R_X86_64_64, R_X86_64_GLOB_DAT and R_AARCH64_GLOB_DAT relocations all have initial
            // values of zero. R_X86_64_JUMP_SLOT and R_AARCH64_JUMP_SLOT relocations have initial
            // values that point into the PLT, but we set these to zero in our post-processing
            // script before HMACing the module. These relocation targets are excluded from our
            // FIPS module boundary because they're used for external function calls, which we
            // cannot verify the addresses of at runtime, and which are by definition outside of
            // the FIPS module anyway.
            replacement = 0;
            break;
        default:
            // We cannot handle other relocation types
            SYMCRYPT_FIPS_ASSERT( FALSE );
            break;
    }

    *target = replacement;
}

void SymCryptModuleFindRelocationInfo(
    _In_ const Elf64_Dyn* const dynStart,
    _Out_ Elf64_Rela_Info* relaInfo)
{
    relaInfo->rela = NULL;
    relaInfo->relaEntryCount = 0;
    relaInfo->pltRela = NULL;
    relaInfo->pltRelaEntryCount = 0;

    size_t relaTotalSize = 0;
    size_t relaEntrySize = 0;
    size_t pltTotalSize = 0;

    for( const Elf64_Dyn* dyn = dynStart; dyn->d_tag != DT_NULL; ++dyn )
    {
        switch( dyn->d_tag )
        {
            case DT_RELA:
                relaInfo->rela = ( Elf64_Rela* ) dyn->d_un.d_ptr;
                break;

            case DT_RELASZ:
                relaTotalSize = dyn->d_un.d_val;
                break;

            case DT_RELAENT:
                relaEntrySize = dyn->d_un.d_val;
                break;

            case DT_JMPREL:
                relaInfo->pltRela = ( Elf64_Rela* ) dyn->d_un.d_ptr;
                break;

            case DT_PLTRELSZ:
                pltTotalSize = dyn->d_un.d_val;
                break;

            case DT_PLTREL:
                // Make sure PLT entries are DT_RELA entries and not DT_REL; we do not suppport
                // the latter
                SYMCRYPT_FIPS_ASSERT( dyn->d_un.d_val == DT_RELA );
                break;

            default:
                break;
        }
    }

    SYMCRYPT_FIPS_ASSERT( relaInfo->rela != NULL );
    SYMCRYPT_FIPS_ASSERT( relaEntrySize == sizeof( Elf64_Rela ) );
    SYMCRYPT_FIPS_ASSERT( relaTotalSize != 0 && relaTotalSize % relaEntrySize == 0 );

    relaInfo->relaEntryCount = relaTotalSize / relaEntrySize;

    // On AMD64 there should not be a PLT section, because we can't currently handle AMD64 PLT
    // relocations
    if( relaInfo->pltRela != NULL)
    {
        SYMCRYPT_FIPS_ASSERT( pltTotalSize != 0 && pltTotalSize % sizeof( Elf64_Rela ) == 0 );
        relaInfo->pltRelaEntryCount = pltTotalSize / sizeof( Elf64_Rela );
    }
}

size_t SymCryptModuleProcessSegmentWithRelocations(
    _In_ const Elf64_Addr module_base,
    _In_ const Elf64_Phdr* const programHeader,
    _In_ const Elf64_Dyn* const dynStart,
    _In_ const Elf64_Rela_Info* const relaInfo,
    _Inout_ SYMCRYPT_HMAC_SHA256_STATE* hmacState )
{
    // The segment that contains relocations consists of the following sections, in this order:
    // .data.rel.ro .dynamic .got .data .bss
    //
    // .data.rel.ro, .dynamic and .got contain relocations, but are not modified by the code itself
    // once the dynamic linker has performed the relocations, so these sections are included in our
    // HMAC calculation.
    //
    // .data includes non-constant global variables which can change at runtime. We cannot reverse
    // these values without tightly coupling this integrity verification implementation to internal
    // implementation details of SymCrypt, so it is not included in our HMAC. The .bss section in
    // the module on disk is usually a different size than at runtime, so we cannot include it in
    // our HMAC either.
    //
    // FipsBoundaryOffset marks the start of the .data section, so we read from the start of the
    // segment up to that offset.
    size_t hashableSectionSize = SYMCRYPT_FORCE_READ64( &SymCryptVolatileFipsBoundaryOffset ) - programHeader->p_offset;
    Elf64_Addr segmentStart = module_base + programHeader->p_vaddr;

    BYTE* segmentCopy = SymCryptCallbackAlloc( hashableSectionSize );
    SYMCRYPT_FIPS_ASSERT( segmentCopy != NULL );

    memcpy( segmentCopy, (const unsigned char*) segmentStart, hashableSectionSize );

    // Some of the entries in the .dynamic section get relocated, but those relocations are not
    // included in the list of relocations given in the .rela.dyn section. Thus, we must process
    // these relocations separately. We find the .dynamic section in the copied buffer based on
    // its offset from the start of the section, which is calculated by subtracting the address
    // of the start of the segment from the address of the .dynamic section in the segment.
    Elf64_Off dynOffsetInBuffer = (Elf64_Addr) dynStart - (Elf64_Addr) segmentStart;
    Elf64_Dyn* dynStartInBuffer = (Elf64_Dyn*) (segmentCopy + dynOffsetInBuffer);

    for( Elf64_Dyn* dyn = dynStartInBuffer; dyn->d_tag != DT_NULL; ++dyn )
    {
        // The following types of .dynamic entries have the module's base address added to
        // their initial value
        if( dyn->d_tag == DT_HASH ||
            dyn->d_tag == DT_STRTAB ||
            dyn->d_tag == DT_SYMTAB ||
            dyn->d_tag == DT_RELA ||
            dyn->d_tag == DT_GNU_HASH ||
            dyn->d_tag == DT_VERSYM ||
            dyn->d_tag == DT_PLTGOT ||
            dyn->d_tag == DT_JMPREL)
        {
            dyn->d_un.d_val -= (Elf64_Xword) module_base;
        }
    }

    // Now we can process the normal relocations listed in the relocation table
    for( size_t i = 0; i < relaInfo->relaEntryCount; ++i )
    {
        const Elf64_Rela* rela = relaInfo->rela + i;

        // Find the relocation within the section. Note that for a shared object module,
        // rela->r_offset is actually a virtual address. Relocations can occur within the .data
        // section, which is outside our FIPS boundary, so any such relocations can be ignored.
        Elf64_Off offsetInBuffer = (Elf64_Off) rela->r_offset - (Elf64_Off) programHeader->p_vaddr;
        if( offsetInBuffer > hashableSectionSize )
        {
            continue;
        }

        Elf64_Xword* target = (Elf64_Xword*) ( segmentCopy + offsetInBuffer);

        SymCryptModuleUndoRelocation( module_base, target, rela );
    }

    // Process the GOT entries from the .rela.plt section. Same as process above, just
    // with a different table.
    for( size_t i = 0; i < relaInfo->pltRelaEntryCount; ++i)
    {
        const Elf64_Rela* rela = relaInfo->pltRela + i;

        Elf64_Off offsetInBuffer = (Elf64_Off) rela->r_offset - (Elf64_Off) programHeader->p_vaddr;
        if( offsetInBuffer > hashableSectionSize )
        {
            continue;
        }

        Elf64_Xword* target = (Elf64_Xword*) ( segmentCopy + offsetInBuffer);

        SymCryptModuleUndoRelocation( module_base, target, rela );
    }

    SymCryptHmacSha256Append( hmacState, segmentCopy, hashableSectionSize );

    SymCryptCallbackFree( segmentCopy );

    return hashableSectionSize;
}

void SymCryptModuleDoHmac(
    _In_ const Elf64_Addr module_base,
    _In_ const Elf64_Dyn* const dynStart,
    _In_ const Elf64_Rela_Info* const relaInfo )
{
    SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
    SYMCRYPT_HMAC_SHA256_EXPANDED_KEY hmacKey;
    SYMCRYPT_HMAC_SHA256_STATE hmacState;
    BYTE actualDigest[SYMCRYPT_HMAC_SHA256_RESULT_SIZE] = {0xFF};

    scError = SymCryptHmacSha256ExpandKey( &hmacKey, SymCryptVolatileFipsHmacKey,
        sizeof(SymCryptVolatileFipsHmacKey) );
    SYMCRYPT_FIPS_ASSERT( scError == SYMCRYPT_NO_ERROR );

    SymCryptHmacSha256Init( &hmacState, &hmacKey );

    const Elf64_Ehdr* header = (Elf64_Ehdr*) module_base;
    const Elf64_Phdr* programHeaderStart = (Elf64_Phdr*) ( module_base + header->e_phoff );

    for( const Elf64_Phdr* programHeader = programHeaderStart;
        programHeader->p_type == PT_LOAD; ++programHeader )
    {
        // Sometimes the virtual address of a segment is greater than its offset into the module
        // file on disk. This means extra NULL bytes will be inserted into the module's memory
        // space at runtime. Those bytes are not part of our FIPS boundary, so we skip over them
        // and always start reading from the segment's virtual address
        Elf64_Addr segmentStart = module_base + (Elf64_Off) programHeader->p_vaddr;

        if( (programHeader->p_flags & PF_W) == PF_W &&
            SYMCRYPT_FORCE_READ64( &SymCryptVolatileFipsBoundaryOffset ) <= programHeader->p_offset + programHeader->p_filesz )
        {
            // If we are processing the final writable segment (containing the .data section which
            // marks the end of our FIPS boundary), then we need to reverse relocations in it
            SymCryptModuleProcessSegmentWithRelocations( module_base, programHeader, dynStart,
                relaInfo, &hmacState );
        }
        else
        {
            // For AMD64/ARM64, non-writeable segments do not contain relocations, so we can write
            // them in their entirety without modification. Note that the size in memory of the
            // section may be larger than the size on disk, but again, the additional size in memory
            // is not part of our FIPS boundary
            // For now we assume that if there are writable segments before the final writable
            // segment that they also contain no relocations
            SymCryptHmacSha256Append( &hmacState, (PCBYTE) segmentStart,
                programHeader->p_filesz );
        }
    }

    SymCryptHmacSha256Result( &hmacState, actualDigest );

    // Verify that the HMAC result matches our expected digest
    SYMCRYPT_FIPS_ASSERT(
        memcmp( actualDigest, SymCryptVolatileFipsHmacDigest, SYMCRYPT_HMAC_SHA256_RESULT_SIZE ) == 0 );
}

void SymCryptModuleVerifyIntegrity()
{
    // Verify that our placeholder values were modified after compile time. The build script
    // should have replaced the placeholder values with their expected values
    SYMCRYPT_FIPS_ASSERT( SYMCRYPT_FORCE_READ64( &SymCryptVolatileFipsHmacKeyRva ) != PLACEHOLDER_VALUE );
    SYMCRYPT_FIPS_ASSERT( SYMCRYPT_FORCE_READ64( &SymCryptVolatileFipsBoundaryOffset ) != PLACEHOLDER_VALUE );

    const Elf64_Addr module_base = (Elf64_Addr) SymCryptVolatileFipsHmacKey -
        SYMCRYPT_FORCE_READ64( &SymCryptVolatileFipsHmacKeyRva );

    const Elf64_Ehdr* header = (Elf64_Ehdr*) module_base;
    SYMCRYPT_FIPS_ASSERT( memcmp(header->e_ident.ident.magic, ElfMagic, sizeof(ElfMagic)) == 0 );
    SYMCRYPT_FIPS_ASSERT( header->e_type == ET_DYN );
    SYMCRYPT_FIPS_ASSERT( header->e_machine == EM_X86_64 || header->e_machine == EM_AARCH64 );
    SYMCRYPT_FIPS_ASSERT( header->e_version == EV_CURRENT );
    SYMCRYPT_FIPS_ASSERT( header->e_ehsize == sizeof(Elf64_Ehdr) );
    SYMCRYPT_FIPS_ASSERT( header->e_phentsize == sizeof(Elf64_Phdr) );

    const Elf64_Phdr* programHeaderStart = (Elf64_Phdr*) ( module_base + header->e_phoff );

    Elf64_Rela_Info relaInfo = {};

    Elf64_Dyn* dynStart = NULL;

    for( unsigned int i = 0; i < header->e_phnum; ++i )
    {
        const Elf64_Phdr* programHeader = programHeaderStart + i;
        if( programHeader->p_type == PT_DYNAMIC )
        {
            dynStart = (Elf64_Dyn*) (module_base + (Elf64_Off) programHeader->p_vaddr);

            SymCryptModuleFindRelocationInfo( dynStart, &relaInfo );

            // We only expect one PT_DYNAMIC segment
            break;
        }
    }

    SymCryptModuleDoHmac( module_base, dynStart, &relaInfo );
}