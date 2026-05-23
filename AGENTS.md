# SymCrypt AI Agent Instructions

## Repository Overview

SymCrypt is Microsoft's core cryptographic function library, used across Windows and other Microsoft products. It is a **FIPS 140-validated**, **security-critical** C library with hand-written assembly for performance-critical paths.

The Microsoft-internal repository is hosted in Azure DevOps. The public GitHub repository is updated periodically, but may not contain the latest code. For Microsoft internal development, you should always use the Azure DevOps repository.

### Language Breakdown
- **C** (C11): All algorithm implementations and library core; extensive use of intrinsics for performance-critical paths.
- **Assembly** (`.symcryptasm`): Used for performance-critical code when intrinsics are unavailable or insufficient. Intrinsics are always preferred over assembly.
- **C++** (C++17): Unit test framework only.
- **Python 3**: Build scripts, ASM translation (`symcryptasm_processor.py`), FIPS integrity tools.
- **Rust**: Experimental new Rust implementation (under `SymCRust` directory, not present on all branches).

### Key Directories

| Directory | Purpose |
|-----------|---------|
| `inc/` | Public headers (`symcrypt.h`), internal headers (`symcrypt_internal.h`), low-level API (`symcrypt_low_level.h`) |
| `lib/` | All algorithm implementations (one file per algorithm or related group) |
| `lib/amd64/` | AMD64 assembly sources (`.symcryptasm` files) |
| `lib/arm64/` | ARM64 assembly sources |
| `lib/i386/` | x86 assembly sources |
| `modules/` | Shared object libraries/DLLs (these constitute FIPS modules on Linux) |
| `unittest/` | Unit test executable, KAT data files (`kat_*.dat`), test infrastructure |
| `test/` | Additional tests (e.g. indirect call perf) (legacy) |
| `scripts/` | Build (`build.py`), test (`test.py`), packaging, ASM processing, version scripts |
| `3rdparty/` | Third-party dependencies (jitterentropy, etc.) |
| `cmake-configs/` | CMake platform detection, toolchain files, compiler flag configuration |
| `conf/` | Input templates (`symcrypt.pc.in`, `buildInfo.h.in`, `symcrypt_internal_shared.inc.in`) consumed by `scripts/version.py` and CMake `configure_file()` |
| `msbuild/` | MSBuild `.props` files for Windows kernel/user-mode builds |
| `gen/` | Code to generate constants and tables (legacy) |
| `nuget/` | NuGet packaging metadata |
| `doc/` | Design documents (notably `doc/breaking_changes.md` for the upcoming-breaking-changes roadmap) |
| `.pipelines/` | Azure DevOps OneBranch CI pipeline definitions |ions |


If you have access to Deep Wiki via MCP or web search, you can use it to ask questions about SymCrypt files. However, Deep Wiki should only be used as a starting point to conserve context, and you must directly confirm anything it tells you, as some of its information may be inaccurate or out-of-date.

---

## Build Instructions

### Prerequisites
- CMake >= 3.13.0 (>= 3.21 to use the `CMakePresets.json` presets)
- Python 3 (required even for raw CMake builds — used for ASM translation and FIPS integrity)
- **Windows**: Visual Studio 2019+ with Windows 10 SDK 18362, MSVC. **Must be running in a developer command prompt which has build tools on the PATH.**
- **Linux**: GCC >= 9.4 or Clang >= 10.0
- **macOS**: Apple Clang
- pip packages: `pip3 install -r scripts/requirements.txt` (pyelftools, for FIPS postprocessing)

### Using `scripts/build.py` (Recommended for MSBuild on Windows)

```bash
# MSBuild (Windows only)
python3 scripts/build.py msbuild

# build.py also supports CMake (Linux/macOS/Windows)
python3 scripts/build.py cmake <build_dir>

# See all options
python3 scripts/build.py cmake --help
```

### CMake Presets

`CMakePresets.json` defines presets for all supported configurations. Use `cmake --list-presets` to see which presets are available on the host machine. Presets with "Cross" in the name can be used for cross-compilation, but agents should do native builds unless explicitly instructed otherwise.

```bash
cmake --preset Linux_AMD64_GCC_Debug
cmake --build --preset Linux_AMD64_GCC_Debug
```

### CMake Options

CMake builds support the following options. Presets include default values, but these can be toggled individually for specific scenarios.

| Option | Default | Description |
|--------|---------|-------------|
| `SYMCRYPT_USE_ASM` | ON | Enable hand-written ASM optimizations |
| `SYMCRYPT_FIPS_BUILD` | ON | Enable FIPS self-tests and integrity checks |
| `SYMCRYPT_TARGET_ARCH` | Host arch | `AMD64`, `X86`, `ARM64` |
| `SYMCRYPT_FIPS_POSTPROCESS` | ON | FIPS integrity hash postprocessing |
| `SYMCRYPT_TEST_LEGACY_IMPL` | OFF | Internal Microsoft-only: legacy RSA32/msbignum benchmarks |
| `SYMCRYPT_TEST_WITH_OPENSSL` | OFF | Enable OpenSSL performance comparison in tests |
| `SYMCRYPT_STRIP_BINARY` | ON | Strip symbols in release builds |

### ASM vs Generic Builds

When `SYMCRYPT_USE_ASM=OFF`, the `SYMCRYPT_IGNORE_PLATFORM` define is set and only portable C implementations are compiled. ASM is supported on:
- Windows: AMD64, ARM64, x86
- Linux: AMD64, ARM64
- macOS: ARM64

### Kernel-Mode vs User-Mode

Kernel-mode builds use MSBuild only (CMake does not support kernel components). The environment is selected by invoking the appropriate macro in the caller's code:
- `SYMCRYPT_ENVIRONMENT_WINDOWS_KERNELMODE_LATEST` (alias for `..._WIN8_1_N_LATER`)
- `SYMCRYPT_ENVIRONMENT_WINDOWS_USERMODE_LATEST` (alias for `..._WIN8_1_N_LATER`)
- `SYMCRYPT_ENVIRONMENT_POSIX_USERMODE` (also aliased as `..._LINUX_USERMODE`)
- Other targeted environments: `..._WINDOWS_BOOTLIBRARY`, `..._WINDOWS_KERNELDEBUGGER`, `..._ELEVATED_DEBUGGER`, `..._WINDOWS_USERMODE_WIN10_SGX`, `..._OPTEE_TA`, `..._GENERIC`

See `inc/symcrypt_internal.h` lines ~3257-3311 for the full list.

---

## Testing

### Running Tests

Tests can be run directly by executing `symcryptunittest.exe`. The location will depend on which build system was used.

- CMake: `build/cmake/<preset>/exe`
- MSBuild: `build/bin/<flavor>/exe`, where `<flavor>` is a Windows architecture/optimization pair, e.g. `amd64fre`

The `test.py` script can also be used to help find and run the unit test executable, but it's preferable to invoke it directly.

```bash
# After building:
python3 scripts/test.py <build_dir>
```

Note that the unit test takes a long time to run. For a release build on a powerful system, it might take 8-10 minutes. Running the "generic" build without CPU-specific optimizations could take upwards of an hour, so this should be avoided. Generally you should run the tests in Debug mode for your host CPU, and let the CI pipeline handle other variants.

### What Tests Cover

1. **Functional correctness**: Known Answer Tests (KAT) from `unittest/kat_*.dat` files covering all algorithms
2. **Cross-implementation comparison** : Validates against other implementations, including CNG/RSA32/msbignum (Windows only) and OpenSSL
3. **Performance benchmarks**: Measures and reports algorithm performance
4. **FIPS self-test validation**: Verifies self-tests run correctly
5. **Negative testing**: Invalid inputs, error paths

### Test Flags

- `+<cpufeature>`: Ensure that CPU feature is present in CPU
- `-<cpufeature>`: Disable CPU feature for SymCrypt
- `+<impl. prefix>`: Run only those implementations that match the prefix
- `-<impl. prefix>`: Do not run the implementations that match the prefix
- `+<alg. prefix>`: Run only those algorithms that match the prefix
- `-<alg. prefix>`: Do not run algorithms that match the prefix

Generally you will only be making changes to one algorithm, so you can run the test more quickly by using `+<alg. prefix>` to only run tests for the modified algorithm. CPU feature flags should only be used when testing architecture-specific optimizations.

You can run the test with `-?` to view a full list of options, including available implementations and algorithm names.

### Unit Test Structure

The unit test executable (`symcryptunittest`) is built from `unittest/` and links against the static SymCrypt library. KAT files are embedded or loaded at runtime.

---

## Code Style and Conventions

### Naming Patterns

- **Public API functions**: `SymCrypt` prefix + PascalCase algorithm + operation
  - Examples: `SymCryptAesExpandKey`, `SymCryptSha256`, `SymCryptEcDhSecretAgreement`
- **Internal functions**: `SymCrypt` prefix, often with `Internal` suffix
  - Example: `SymCryptAesExpandKeyInternal`
- **Types**: `SYMCRYPT_` prefix + UPPER_CASE
  - Examples: `SYMCRYPT_AES_EXPANDED_KEY`, `SYMCRYPT_ERROR`, `SYMCRYPT_SHA256_STATE`
- **Pointer types**: `P` prefix for pointer, `PC` for const pointer
  - Examples: `PSYMCRYPT_AES_EXPANDED_KEY`, `PCBYTE`
- **Constants/Macros**: `SYMCRYPT_` prefix + UPPER_CASE
- **Global variables**: `g_SymCrypt` prefix
  - Example: `g_SymCryptCpuFeaturesNotPresent`
- **Calling convention**: All public functions use `SYMCRYPT_CALL` annotation

### File Organization

- **One algorithm per file** (or closely related group): `aes-key.c`, `sha256.c`, `gcm.c`
- **Variant implementations**: suffix indicates target: `aes-xmm.c`, `aes-ymm.c`, `aes-zmm.c`, `aes-neon.c`
- **Platform-specific ASM**: in `lib/amd64/`, `lib/arm64/`, `lib/i386/` subdirectories
- **Environment files**: `env_*.c` files configure platform-specific behavior
- **Self-test files**: `*_selftest.c` or `fips_selftest.c`
- **Pattern files**: `*_pattern.c` for code that is instantiated multiple times with different parameters

### Header Structure

| Header | Purpose | Stability |
|--------|---------|-----------|
| `inc/symcrypt.h` | Public API — the only header callers should include | Stable across minor versions |
| `inc/symcrypt_low_level.h` | Low-level API for advanced use | NOT stable across releases* |
| `inc/symcrypt_internal.h` | Internal structures, inlines, platform detection | Internal only* |
| `lib/precomp.h` | Precompiled header for library sources | Internal only |
| `lib/sc_lib.h` | Internal library-only declarations | Internal only |

Note that although `symcrypt_low_level.h` and `symcrypt_internal.h` are intended to be internal-only, any function or structure that is exposed as part of the public ABI (i.e. exported from a shared object library) cannot be changed without introducing a breaking change. **Do not make breaking changes** unless explicitly instructed otherwise.

### SAL Annotations

All public API functions use SAL annotations for buffer parameters:
```c
SYMCRYPT_ERROR
SYMCRYPT_CALL
SymCryptAesExpandKey(
    _Out_               PSYMCRYPT_AES_EXPANDED_KEY  pExpandedKey,
    _In_reads_(cbKey)   PCBYTE                      pbKey,
                        SIZE_T                      cbKey );
```

### Code Style/Structure

- Every `.c` file in `lib/` includes `precomp.h` (typically as the first non-comment line, after the copyright header).
- Copyright header: `// Copyright (c) Microsoft Corporation. Licensed under the MIT license.`
- Use `SYMCRYPT_NOINLINE` to prevent inlining of security-sensitive functions.
- Use `SYMCRYPT_FORCE_READ*` / `SYMCRYPT_FORCE_WRITE*` to ensure the compiler does not optimize away memory accesses (e.g. for side channel safety).
- Multi-character constants are used for fatal error codes: `SymCryptFatal( 'init' )`.
- Line length is 100 characters. This may be exceeded slightly when using a single line results in better readability, but avoid extremely long lines (>120 characters).
- When breaking a function call or macro invocation across multiple lines, use one line per parameter. Exceptions may be made for multiple consecutive related parameters, e.g. `a0`, `a1`, `a2` for accumulators in CLMUL code.
- Spaces should be used after opening parentheses and before closing parentheses, e.g. `foo( bar )`. However, these can be omitted when many nested parentheses would make it unwieldy.
- Unless it's important to understanding the function of the code, do not include comments explaining what a previous iteration of the code did, especially if that iteration only existed during development and was never checked in to the main branch.

---

## Security-Critical Guidance

### Threat Model

Bug triage and code review must be grounded in SymCrypt's specific threat model:

- **Caller is trusted.** SymCrypt runs in-process and does not defend against in-process attackers or invalid API inputs (bad pointers, wrong buffer sizes). Crashing on such inputs is acceptable; input validation is the caller's responsibility. Isolation, when needed, is provided by the execution environment.
- **Serialized data is untrusted.** Imported/parsed data may be attacker-controlled. All length fields and structural assumptions must be validated against the buffer before use. Any out-of-bounds access or other UB reachable from a well-formed buffer is a SymCrypt bug.
- **Secret data must be processed in constant time** to prevent timing side channels.
  - Secret data includes (non-exhaustively) private keys, plaintexts, padding validity (avoid padding oracles), and any value derived from them.
  - Speculative-execution attacks (e.g. Spectre) are in scope and mitigated best-effort via coding practices and compiler flags. Power analysis, EM, and fault injection are out of scope.
  - Buffers holding secret data must be wiped via constant-time operations before being freed or going out of scope.
- **Threading.** The library is safe to use concurrently across threads operating on independent objects (a few internal globals are updated atomically). Individual SymCrypt objects are not thread-safe unless explicitly documented as such — e.g., a hash state cannot be updated from two threads at once.
- **Randomness.** SymCrypt's DRBG is trusted once seeded; sourcing entropy for the seed is the caller's/environment's responsibility.

### Constant-Time Requirements

**This is the most important rule.** Any code processing secret data MUST be constant-time:

1. **No secret-dependent branches**: Never use `if/else` or ternary operators where the condition depends on secret data
2. **No secret-dependent memory access**: Array indices must not depend on secret values (prevents cache-timing attacks)
3. **No secret-dependent loop counts**: Loop iteration count must be fixed or depend only on public parameters
4. **Use `SYMCRYPT_FORCE_READ*` macros**: Prevent compiler optimizations that introduce timing variations
5. **Use `volatile` where needed**: Prevent the compiler from optimizing away constant-time patterns
6. **Do not use unsafe arithmetic**: Division and modulo are not side-channel safe

Example of correct constant-time comparison (from `equal.c`):
```c
// Accumulate XOR differences — no early exit
neq |= SYMCRYPT_FORCE_READ32((volatile UINT32 *)p1) ^ SYMCRYPT_FORCE_READ32((volatile UINT32 *)p2);
```

### Side-Channel Resistance

- AES implementations MUST use AES-NI/NEON on platforms that support them (table-based AES is NOT side-channel safe)
- The `SYMCRYPT_IGNORE_PLATFORM` flag disables optimized implementations — this is only for testing and non-security contexts
- Algorithms explicitly NOT side-channel safe: table-based AES (`lib/aes-c.c`, used when AES-NI/NEON unavailable or `SYMCRYPT_USE_ASM=OFF`), DES / 3DES / DESX (table-based via `DesTables.c`), RC2 (`lib/rc2.c`), RC4 (`lib/rc4.c`).

### FIPS 140 Self-Test Obligations

- Self-tests are defined in `lib/fips_selftest.c`
- When `SYMCRYPT_FIPS_BUILD=ON`, the define `SYMCRYPT_MODULE_DO_FIPS_SELFTESTS=1` is set
- Self-tests MUST pass before any algorithm can be used — failure calls `SymCryptFatal`
- The service indicator (`lib/service_indicator.c`) tracks which operations are FIPS-approved
- **Never skip or weaken self-tests** — they are a FIPS certification requirement
- New algorithms that need FIPS approval must add entries to `fips_selftest.c`

### Fatal Error Handling

- `SymCryptFatal(code)` terminates the process (user mode) or bugchecks (kernel mode)
- Fatal errors are unrecoverable — the library state may be inconsistent after one
- Fatal errors are triggered by: API version mismatch, self-test failure, internal consistency violations
- **Never catch or suppress fatal errors**

### Service Indicator Rules

- The service indicator (`lib/service_indicator.c`) reports whether an operation is FIPS-approved
- It validates algorithm + key size + mode combinations against the approved list
- Any new algorithm or mode must be added to the service indicator tables if FIPS-approved

---

## Platform/Architecture Awareness

### Conditional Compilation Patterns

```c
#if SYMCRYPT_CPU_X86 | SYMCRYPT_CPU_AMD64
    // x86/x64 specific code
#endif

#if SYMCRYPT_CPU_ARM64
    // ARM64 specific code
#endif

#if SYMCRYPT_MS_VC
    // MSVC-specific intrinsics
#elif SYMCRYPT_GNUC
    // GCC/Clang intrinsics
#endif
```

Platform macros (defined in `symcrypt_internal.h`):
- `SYMCRYPT_PLATFORM_WINDOWS`, `SYMCRYPT_PLATFORM_APPLE`, `SYMCRYPT_PLATFORM_UNIX`
- `SYMCRYPT_CPU_X86`, `SYMCRYPT_CPU_AMD64`, `SYMCRYPT_CPU_ARM`, `SYMCRYPT_CPU_ARM64`
- `SYMCRYPT_MS_VC`, `SYMCRYPT_GNUC`

### CPU Feature Detection

`lib/cpuid.c` detects CPU features at runtime:
- x86/AMD64: CPUID-based detection for AES-NI, AVX2, AVX-512, PCLMULQDQ, SHA-NI, RDRAND, RDSEED, etc.
- ARM64: Feature detection via OS APIs or exception handling
- Features stored in `g_SymCryptCpuFeaturesNotPresent` (bitmask of features NOT available)

### Dispatch Mechanisms

There are two distinct dispatch mechanisms in SymCrypt:

**1. Block-cipher / hash implementation dispatch** (CPU-feature based):
- Implementations live in per-feature files: `aes-xmm.c`, `aes-ymm.c`, `aes-zmm.c`, `aes-neon.c`, `aes-c.c` (table fallback), `aes-asm.c` (calling per-arch asm). Hash algorithms follow the same pattern (`sha256-xmm.c`, `sha512-ymm.c`, etc.).
- Selection happens through the `SYMCRYPT_BLOCKCIPHER` virtual tables in `lib/aes-default.c` and `lib/aes-default-bc.c`, gated by `g_SymCryptCpuFeaturesNotPresent` (populated by `lib/cpuid.c`).
- If ASM is compiled out (`SYMCRYPT_USE_ASM=OFF` -> `SYMCRYPT_IGNORE_PLATFORM` set), only the portable C path is built.

**2. Modular-arithmetic format dispatch** (asymmetric crypto):
- `lib/a_dispatch.c` populates `g_SymCryptModFns[]` with FDEF implementations (`FDEF_GENERIC`, `FDEF_MONTGOMERY`, `FDEF369_MONTGOMERY`, plus AMD64-specific `MULX256`/`MULXP384`/`MULX1024` variants and ARM64-specific variants). This is *not* about CPU features per se -- it selects the most efficient modular representation for the specific modulus size and parity.

### SymCryptAsm Processing

`.symcryptasm` files are **not** raw assembly — they are processed by `scripts/symcryptasm_processor.py`:
1. `.symcryptasm` → (Python processor) → `.cppasm`
2. `.cppasm` → (C preprocessor) → `.asm` or `.S`
3. Final file assembled by MASM (Windows) or GAS (Linux/macOS)

**Never edit generated `.asm`/`.S` files directly** — always modify the `.symcryptasm` source.

---

## Versioning and Changelog

### Version File

`version.json` contains the current version. The version is read by `scripts/version.py` and injected into the build.

### Semantic Versioning Policy

- **Major** (API version): Incremented for breaking API/ABI changes.
- **Minor**: New features, new algorithms, non-breaking additions
- **Patch**: Bug fixes, security fixes, performance improvements with no API changes

### Updating for Releases

Version management should normally be done by human maintainers. Do not modify the version unless asked to.

1. Update `version.json` with the new version numbers
2. Add a new section at the top of `CHANGELOG.md` with format: `# Version X.Y.Z`
3. List all changes as bullet points under the version heading
4. During development, changes accumulate under the placeholder `# Version x.y.z` header

### Changelog File

The changelog must be updated when adding new externally visible functionality (e.g. new APIs) or fixing bugs. It does not need to be updated for internal-only changes, such as build system changes, file reorganization, CodeQL bugfixes that have no functional impact, etc.

The format of entries in the changelog file is as follows.

```markdown
# Version 103.12.0

- Add ZMM (AVX512) implementation of AES-GCM: improves performance by up to 35% on supported hardware
- Fix heap buffer overflow in `SymCryptXmssSign` when signing with XMSS^MT parameter sets
```

---

## Common Pitfalls — Things You Must NEVER Do

1. **Introduce timing side-channels**: No secret-dependent branches, memory accesses, or loop counts. This is the #1 rule for this codebase.

2. **Skip or weaken FIPS self-tests**: Any new algorithm used in FIPS mode needs a corresponding self-test in `fips_selftest.c`.

3. **Break ABI compatibility in a minor/patch release**: Structure sizes, function signatures, and calling conventions must not change without a major version bump. See `doc/breaking_changes.md`.

4. **Use platform-dependent type sizes in structures**: Use `UINT32`, `UINT64`, `BYTE` — NOT `int`, `long`, `size_t` in persisted structures. Structure sizes must be consistent across platforms.

5. **Modify generated files directly**: Never edit `.asm`, `.S`, or `.cppasm` outputs. Edit the `.symcryptasm` source files in `lib/amd64/`, `lib/arm64/`, or `lib/i386/`.

6. **Use `memcpy` on SymCrypt data structures**: Internal structures contain pointers/offsets that are not relocatable. Use the provided copy functions.

7. **Add external dependencies to the core library**: SymCrypt must remain self-contained for kernel-mode and embedded use.

8. **Use compiler built-ins that may not be constant-time**: e.g., `memcmp` for secret comparison — use `SymCryptEqual` instead.

9. **Ignore the `SYMCRYPT_CALL` annotation**: All exported functions must use it. Missing it is an ABI break on Windows x86.

10. **Introduce undefined behavior**: This is a security library — UB can and will be exploited by compilers or attackers.

---

## PR and Contribution Workflow

### Branch Strategy

- **`main`**: Latest validated code
- **`user/<alias>/*`**: Personal working branches for development
- **`feature/<id>`**: Larger features or pre-standard algorithm implementations
- **`CONF-*`**: Confidential security fixes (internal only, not merged to main until disclosure)

Branch management and publishing to GitHub will always be done by human maintainers. **NEVER** push changes to GitHub; this must always be done by human maintainers to prevent premature disclosure of confidential fixes. If working on a confidential fix (any MSRC case or CVE), always ask the human contributor to ensure the appropriate branch is being used.

### Workflow

1. Create `user/<alias>/<feature>` branch from `main`
2. Develop and locally build + test
3. Submit PR to merge into `main`

### CI Expectations

PRs trigger the OneBranch pipelines (`.pipelines/OneBranch.WindowsUndocked.PullRequest.yml`, `.pipelines/OneBranch.PullRequest.yml`) which:
- Builds all supported platform/architecture/compiler combinations
- Runs the full unit test suite on CI-supported configurations
- Runs all required security and static analysis tools (CredScan, PoliCheck, CodeQL, ...)

All CI checks must pass before merge.

### Code Review Norms

- **Security sensitivity**: All changes are reviewed with side-channel and correctness implications in mind
- **ABI impact**: Any change to public headers or exported symbols requires explicit ABI impact assessment

### PR Checklist

- [ ] No timing side-channels introduced
- [ ] FIPS self-tests added/updated if new algorithm added
- [ ] Service indicator updated if new FIPS-approved operation added
- [ ] CHANGELOG.md updated
- [ ] Builds clean on all supported platforms
- [ ] Unit tests pass
- [ ] SAL annotations on all new public API functions
- [ ] `SYMCRYPT_CALL` on all new exported functions
