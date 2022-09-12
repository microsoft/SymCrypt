# Introduction
SymCrypt is the core cryptographic function library currently used by Windows.

## History
The library was started in late 2006 with the first sources committed in Feb 2007.
Initially the goal was limited to implement symmetric cryptographic operations, hence the name.
Starting with Windows 8, it has been the primary crypto library for symmetric algorithms.

In 2015 we started the work of adding asymmetric algorithms to SymCrypt. Since the 1703 release of Windows 10,
SymCrypt has been the primary crypto library for all algorithms in Windows.

## Goals
Like any engineering project, SymCrypt is a compromise between conflicting requirements:
- Provide safe implementations of the cryptographic algorithms needed by Microsoft products.
- Run on all CPU architectures supported by Windows.
- Good performance.
- Minimize maintenance cost.
- Support FIPS 140-2 certification of products using SymCrypt.
- Provide high assurance in the proper functionality of the library.

# Cloning the Repo
In some of our Linux modules, SymCrypt uses [Jitterentropy](https://github.com/smuellerDD/jitterentropy-library)
as a source of FIPS-certifiable entropy. To build these modules, you will need to ensure that the
jitterentropy-library submodule is also cloned. You can do this by running
`git submodule update --init -- jitterentropy-library` after cloning.

The SymCryptDependencies submodule provides the RSA32 and msbignum implementations which are used as benchmarks
in the unit tests when compiled on Windows. Due to licensing restrictions, we cannot release these libraries
publicly, so this submodule will only be cloneable by Microsoft employees with access to our private
Azure DevOps repository. If you are external to Microsoft, you can ignore this submodule. It is only used in
the unit tests and does not change the behavior of the SymCrypt product code.

# Building
## Prerequisites
SymCrypt can be compiled with CMake >= 3.13.0 and Visual Studio 2019 (with Windows 10 SDK version 18362) on Windows
or gcc 7.4.0 or clang 10.0.0 on Linux. Note that CMake ships with Visual Studio 2019; you can use Visual Studio's
included CMake by setting `$env:PATH="C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\;${env:PATH}"`.

Python 3 is also required for translation of SymCryptAsm, and for building the SymCrypt module with integrity check.
The integrity check additionally requires pip and pyelftools: `pip3 install -r ./scripts/requirements.txt`

## Supported Configurations
SymCrypt has pure C implementations of all supported functionality. These "generic" implementations are designed to
be portable to various architectures. However, they do not offer optimal performance because they do not take
advantage of CPU-specific optimizations. To that end, we also have hand-written assembly implementations of
performance-critical internal functions. Our CMake build scripts do not currently support ASM optimizations on all
combinations of architectures and platforms; the Build Instructions section below lists some of the currently supported
combinations, and we're working on adding support for more. 

The ability to build SymCrypt on any particular platform or architecture, with or without ASM optimizations, does not
imply that it has been tested for or is actively supported by Microsoft on that platform/architecture. While we make
every effort to ensure that SymCrypt is reliable, stable and bug-free on every platform we run on, the code in this
repository is provided *as is*, without warranty of any kind, express or implied, including but not limited to the
warranties of merchantability, fitness for a particular purpose and noninfringement (see our [LICENSE](./LICENSE)).

## Build Instructions
1. For Microsoft employees building the library internally, to include msbignum and RSA32 implementation benchmarks in the unit tests:
    1. Make sure the SymCryptDependencies submodule is initialized by following the steps above (`git submodule update --init`)
    1. In step 4 below, add the additional cmake argument `-DSYMCRYPT_INTERNAL_BUILD=1`
1. Run `cmake -S . -B bin` to configure your build. You can add the following optional CMake arguments to change build options:
    * `-DSYMCRYPT_TARGET_ARCH=<AMD64|X86|ARM64>` to choose a target architecture. If not specified, it will default to the host system architecture.
      * To cross-compile for Windows X86 from Windows AMD64, you must also use `-A Win32`
      * To cross-compile for Linux ARM64, you must also use `--toolchain=cmake-configs/Toolchain-Clang-ARM64.cmake`
    * `-DSYMCRYPT_USE_ASM=<ON|OFF>` to choose whether to use assembly optimizations. Defaults to `ON`. 
    * `-DSYMCRYPT_FIPS_BUILD=<ON|OFF>` to choose whether to enable FIPS self-tests in the SymCrypt shared object module. Defaults to `ON`. Currently only affects Linux builds.
    * For a release build, specify `-DCMAKE_BUILD_TYPE=Release`
1. `cmake --build bin`
    * Optionally, for a release build on Windows, specify `--config Release`
    * Optionally specify `-jN` where N is the number of processes you wish to spawn for the build

After successful compilation, the generated binaries will be placed in the following directories relative
to your build directory:
* `lib` - static libraries
* `module` - shared object libraries (currently only on Linux)
* `exe` - unit tests

# Testing
The SymCrypt unit test runs extensive functional tests on the SymCrypt library. On Windows it also compares results
against on other implementations such as the Windows APIs CNG and CAPI, and the older crypto libraries rsa32 and
msbignum, if they are available. It also provides detailed performance information.

# Versioning and Servicing
As of version 101.0.0, SymCrypt uses the version scheme defined by the
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) specification. This means:

- Major version changes introduce ABI and/or API breaking changes
- Minor version changes introduce backwards compatible additional functionality or improvements, and/or bug fixes
- Patch version changes introduce backwards compatible bug fixes

The initial open source release started at version 100 for compatibility with our previous
internal versioning scheme.

Regarding servicing, our strong recommendation is that distro vendors and application developers regularly
update to the latest version of SymCrypt and SymCrypt engine for both security fixes and 
functionality/performance improvements. We take care to maintain a stable API and ABI for SymCrypt and have
a suite of strong regression tests, and staying on the current version prevents the need for complex
and potential riskier backports.

We will support long-term servicing of specific releases for security fixes. Details of this plan will be
released publicly in the future.

# Security Bugs
If you believe you have found a problem that affects the security of this code, please do **NOT** create an issue
or pull request, but instead email your comments to secure@microsoft.com. See [SECURITY.md](SECURITY.md) for more info.

# Contribute
We love to receive comments and suggestions. Unfortunately we cannot accept external code contributions at this time.
Cryptographic code is considered highly sensitive by many of our large customers.
We have some very big customers who put great value in the assurance of the crypto code used in their organization.
By restricting the coding to a handful of employees we can greatly reduce the (perceived) risk of malicious contributions.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.


