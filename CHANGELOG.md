# Version x.y.z

New changes will be listed here as they are developed. The version number is determined
prior to the creation of a new release, based on the changes contained in that release.

# Version 103.4.1
- Add retpoline guard flags for undocked Windows build
- Support ARM32 for Linux

# Version 103.4.0

- Extended SymCrypt support for XTS-AES adding support for 128-bit tweak and ciphertext-stealing
- Added support for salt length detection in RSA-PSS verification
- Export various constant time operations from SymCrypt Linux modules
- Added support for nonce sizes other than 12 bytes for AES-GCM
- Add FIPS status indicator

# Version 103.3.2

- Performance improvements for ECC NIST prime curves
- Performance improvements for modular arithmetic
- Added maximum iteration count for (Ec)Dsa signing
- Additional checks for OS support of AVX512 registers on Windows
- Various build system tweaks

# Version 103.3.1

- Temporarily disable use of AVX in SHA-2

# Version 103.3.0

- Add SymCryptEcurveCreate and SymCryptEcurveBufferSizesFromParams
- Address some problems with building for 32-bit platforms
- Update documentation around exceptions
- Fix some Windows test module issues

# Version 103.2.0

- Add HMAC-SHA-3 implementations

# Version 103.1.0

- Add SHA-3 based algorithms: SHAKE, cSHAKE, KMAC

# Version 103.0.1

- Linux RNG improvements and additional testing

# Version 103.0.0

- Add SRTP-KDF and SSH-KDF implementations
- Add optimized SHA-2 implementations
- Add SHA-3 implementation
- Fix integer truncation issue in 32-bit Linux builds
- Refactor CMake files to simplify build steps and increase flexibility
- Fix bug for SymCryptRsakeyGenerate for encrypt-only keys
- Create and test against simple SymCrypt Windows test module (DLL)
- Remove the module export of g_SymCryptFipsSelftestsPerformed and replace it with SymCryptFipsGetSelftestsPerformed
- Enable SymCrypt unit tests to drive a dynamically-linked module
- Fix unit test failure importing DH key to CNG
- Removed Linux embedded module, as generic ARM64 module is the same
- Rejig CPUID logic for VAES and AVX
- Disable AVX2 in Windows boot environment

# Version 102.0.0

- Breaking change to Asymmetric key generation and import handling, sanitizing flags required for FIPS
- Trim symbols exposed in SymCrypt module to those specified in symcrypt.h
- Introduce logic enabling FIPS per-key tests to be deferred to before first use, rather than at generation time

# Version 101.3.0

- Fix for OpenEnclave binary to workaround clang bug
- Fix SymCryptRsaPssVerify to return SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE for invalid signatures, rather than SYMCRYPT_INVALID_ARGUMENT
- Fix for SymCryptShortWeierstrassAddSideChannelUnsafe which is only use in ECDSA verification on SW curves
  - An owner of a private ECC key could create an invalid signature that SymCrypt would verify, leaking their private key in the process

# Version 101.2.0

- Added key pairwise consistency tests for RSA, DSA, DH, ECDSA and ECDH key generation, per FIPS 140-3 requirements
- Added Session APIs for AES-GCM
  - For Encryption, this enables multithreaded IV generation within the SymCrypt FIPS boundary
  - For Decryption, this enables multithreaded replay protection detecting reuse of IVs in received messages

# Version 101.1.0

- Support for Group 20 in SAE method

# Version 101.0.0

- Support stable ABI: change SYMCRYPT_ERROR definition so that error values no longer change with version changes
- Support proper shared library versioning in CMake build scripts
- Support for FIPS integrity verification on ARM64
- Additional CMake build system changes

# Version 100.21

- Fix bug in SymCryptDlkeySizeofPrivateKey
- Add SymCryptDlkeySetPrivateKeyLength API
- Add SymCryptHkdfExtractPrk API
- Add SP800-108 self tests for HMAC-SHA512
- Use _mmXXX_storeu_siXXX intrinsics in AES-XTS w/VAES
- Add macros for volatile memory access to avoid MSVC C4746 warning in unit tests