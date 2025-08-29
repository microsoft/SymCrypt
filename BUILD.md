## Prerequisites
SymCrypt can be compiled with CMake >= 3.13.0 and Visual Studio 2019 (with Windows 10 SDK version 18362) on Windows
or gcc 7.4.0 or clang 10.0.0 on Linux. Note that CMake ships with Visual Studio 2019; you can use Visual Studio's
included CMake by setting `$env:PATH="C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\;${env:PATH}"`.

Python 3 is also required for translation of SymCryptAsm, and for building the SymCrypt module with integrity check.
The integrity check additionally requires pip and pyelftools: `pip3 install -r ./scripts/requirements.txt`

## Platform and Architecture Support
SymCrypt has pure C implementations of all supported functionality. These "generic" implementations are designed to
be portable to various architectures. However, they do not offer optimal performance because they do not take
advantage of CPU-specific optimizations. To that end, we also have hand-written assembly implementations of
performance-critical internal functions. Our CMake build scripts do not currently support ASM optimizations on all
combinations of architectures and platforms; the table below lists currently supported
combinations.

SymCrypt supports a variety of operating systems, CPU architectures, and runtime environments, but due to functionality
gaps in the build systems we use, not every combination is supported by every build system. Specifically, because
CMake does not currently support building kernel mode components, we also support MSBuild for building kernel-mode
libraries on Windows. Internally, we previously used Razzle as our legacy build system, but SymCrypt's support
for Razzle builds is on a deprecation path and will be removed in a future release. Additionally, it has not been
tested with the public open source version of Razzle, and is unlikely to work with it.

Note: AMD64 is the terminology Windows uses for x86-64.

### Supported Configurations

| Operating Environment | Architecture      | Supported compilers | ASM enabled | Static lib + unit tests | Dynamic lib | 
| --------------------- | ----------------- | ------------------- | ----------- | ----------------------- | ----------- |
| Windows kernel mode   | AMD64, ARM64      | MSVC                | ✅          | ✅                      | ✅          |
| Windows user mode     | AMD64, ARM64, x86 | MSVC                | ✅          | ✅                      | ✅          |
| Linux user mode       | AMD64, ARM64      | GCC, Clang          | ✅          | ✅                      | ✅          |
| Linux user mode       | x86               | GCC, Clang          | ❌          | ✅                      | ✅          |
| macOS                 | AMD64, ARM64      | Apple Clang         | ❌          | ✅                      | ✅          |

The ability to build SymCrypt on any particular platform or architecture, with or without ASM optimizations, does not
imply that it has been tested for or is actively supported by Microsoft on that platform/architecture. While we make
every effort to ensure that SymCrypt is reliable, stable and bug-free on every platform we run on, the code in this
repository and the binaries we release are provided *as is*, without warranty of any kind, express or implied, including
but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement
(see our [LICENSE](./LICENSE.txt)).

## Build Instructions
For Microsoft employees building the library internally, to include msbignum and RSA32 implementation benchmarks in
the unit tests, make sure the SymCryptDependencies submodule is initialized by following the steps above
(`git submodule init && git submodule update --checkout unittest/SymCryptDependencies`). When building, specify
`/p:SymCryptTestLegacyImpl=true` for MSBuild, or `-DSYMCRYPT_TEST_LEGACY_IMPL=ON` for CMake. This only affects the
unit tests, and does not change the functionality of the SymCrypt library itself.

### Using Python scripts
Building SymCrypt can be complicated due to the number of platforms, architectures and targets supported. To improve
ease of use and have a consistent build solution that can be leveraged by both developers and our automated CI
pipelines, we have created a set of Python scripts to help with building, testing and packaging. You can run
`scripts/build.py --help` to get help with supported options.

1. To build SymCrypt for Windows or Linux using the CMake build system, run `scripts/build.py cmake build_dir` where `build_dir` is the desired build output directory.
    * To see additional options, run `scripts/build.py cmake --help`.
    * On Windows, the build script also supports MSBuild. To use MSBuild, run `scripts\build.py msbuild`. The output directory for MSBuild is always `build\bin`.
1. To run the unit tests after a build has finished, run `scripts/test.py build_dir`.
    * Additional positional arguments will be passed directly to the unit test executable.
1. To package up the built binaries into an archive, run `scripts/package.py build_dir arch configuration module_name release_dir`, where:
    * `build_dir` is the build output directory
    * `arch` is the architecture that the build was created for
    * `configuration` is the build configuration (Debug, Release, Sanitize)
    * `module_name` is the name of the module you wish to package (currently only relevant for Linux builds)
    * `release_dir` is the output directory for the release archive

### Building with CMake
If you don't want to use the Python helper scripts, or if they do not support the specific build flags you desire,
you can build SymCrypt by directly invoking CMake. Note that Python is still required for translating SymCryptAsm
and building the Linux modules with FIPS integrity checks.

1. Run `cmake -S . -B bin` to configure your build. You can add the following optional CMake arguments to change build options:
    * `-DSYMCRYPT_TARGET_ARCH=<AMD64|X86|ARM64>` to choose a target architecture. If not specified, it will default to the host system architecture.
      * To cross-compile for Windows X86 from Windows AMD64, you must also use `-A Win32`
      * To cross-compile for Linux ARM64, you must also use `--toolchain=cmake-configs/Toolchain-Clang-ARM64.cmake`
    * `-DSYMCRYPT_USE_ASM=<ON|OFF>` to choose whether to use assembly optimizations. Defaults to `ON`.
    * `-DSYMCRYPT_FIPS_BUILD=<ON|OFF>` to choose whether to enable FIPS in the SymCrypt shared object module. Defaults to `ON`. Currently only affects Linux builds. Disabling this reduces dependencies and avoids FIPS postprocessing.
    * `-DSYMCRYPT_STRIP_BINARY=<ON|OFF>` to choose whether to strip the binary. Defaults to `ON`.
    * `-DSYMCRYPT_FIPS_POSTPROCESS=<ON|OFF>` to choose whether to run the FIPS postprocess script. Defaults to `ON`.
    * For a release build, specify `-DCMAKE_BUILD_TYPE=RelWithDebInfo`
1. `cmake --build bin`
    * Optionally, for a release build on Windows, specify `--config Release`
    * Optionally specify `-jN` where N is the number of processes you wish to spawn for the build

After successful compilation, the generated binaries will be placed in the following directories relative
to your build directory:
* `lib` - static libraries
* `module` - shared object libraries (currently only on Linux)
* `exe` - unit tests

### Building with MSBuild
SymCrypt also supports building with MSBuild on Windows. This is primarily intended for Microsoft-internal use in
official builds, for compatibility with the Windows engineering system. If you wish to build directly with MSBuild,
bypassing the Python helper script, you can run `msbuild /p:Platform=<platform> /p:Architecture=<arch> symcrypt.sln`.
Note that Python is still required for translating SymCryptAsm. The output directory for MSBuild is always `build\bin`,
and all compiled outputs are placed in this directory.

## Building for Linux

Requires the following packages on Debian-based systems to build:
```
apt update
apt -y install --no-install-recommends \
    cmake \
    python3-pyelftools \
    build-essential \
    gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf
```
`python3-pyelftools` is for integrity verification and `gcc-arm-linux-gnueabihf` `g++-arm-linux-gnueabihf` are for ARM cross compile
And for running the test:
```
apt -y install --no-install-recommends qemu-user
```

To build and test for example for arm:
```
python3 scripts/build.py cmake --arch arm --toolchain cmake-configs/Toolchain-GCC-ARM.cmake bin_arm
qemu-arm -L /usr/arm-linux-gnueabihf/ ./bin_arm/exe/symcryptunittest -rsa -dsa -dh -ec -int -mod dynamic:bin_arm/module/generic/libsymcrypt.so
```

## Building for macOS
Building on macOS requires the following prerequisites:
- XCode (for developer tools, headers, and frameworks)
- CMake
- Python 3 (for build scripts)

As described above, the easiest way to build for macOS is to use the Python build script. As we don't currently support ASM
optimizations on Mac, you must set the `--no-asm` flag. If you are instead building directly with CMake, you must set `-DSYMCRYPT_USE_ASM=OFF`.

## Performance comparison with OpenSSL
`symcryptunittest.exe` can be used to compare and measure performance of algorithms provided by SymCrypt and OpenSSL.
On Windows `symcryptunittest.exe` would have to be compiled with OpenSSL. `nasm` and  `strawberryperl` are
prerequisites to building OpenSSL.

```
winget install nasm strawberryperl
python3 .\scripts\build.py cmake bin --config Release --openssl-build-from-source
```

And on Linux we can use OpenSSL installed by system's package manager.

```
sudo apt install -y libssl-dev
python3 ./scripts/build.py cmake bin --config Release --openssl
```

To build OpenSSL on Linux we need to install following prerequisites.

```
sudo apt install -y nasm perl
python3 ./scripts/build.py cmake bin --config Release --openssl-build-from-source
```
