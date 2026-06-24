# SymCrypt NuGet Package

This directory contains the NuGet package configuration for SymCrypt. The package
ships native binaries for both Windows and Azure Linux under the standard
`runtimes/<rid>/native/` layout.

## Building the NuGet Package

Building the package manually is time-consuming and is not recommended, unless you have to make
changes to the package build process itself. Normally the package should be built from the
Azure DevOps pipeline; see [nuget-windows-undocked.yml](../.pipelines/templates/nuget-windows-undocked.yml)

1. Build SymCrypt for the target platforms supported by the NuGet package:
   - Windows AMD64 and ARM64 (`scripts/build.py msbuild` for each arch)
   - Azure Linux AMD64 and ARM64 (Clang Release preset)
2. Use [package.py](../scripts/package.py) to package each build flavor.
3. Copy the package contents to their respective locations specified in symcrypt.nuspec:
   - Windows AMD64: `../pkg/win-x64/`
   - Windows ARM64: `../pkg/win-arm64/`
   - Linux AMD64:   `../pkg/linux-x64/`   (contains `inc/symcrypt_no_sal.h` and `lib/libsymcrypt.so`)
   - Linux ARM64:   `../pkg/linux-arm64/` (contains `lib/libsymcrypt.so`)
4. Create the package using the NuGet CLI, explicitly specifying the package version:
   ```
   nuget pack symcrypt.nuspec -Version <SymCrypt Package Version>
   ```

The pipeline copies the Linux `.so` from the SONAME-versioned binary
(`libsymcrypt.so.<MAJOR>.<MINOR>.<PATCH>`) inside the Linux build artifact into the
unversioned `libsymcrypt.so` slot before packing. This is required because `.nupkg` is
zip-based and does not preserve Unix symlinks or the SONAME chain.

## Usage

### Windows (MSVC C++)

The test project under the `test/cpp` directory shows how to consume the NuGet package from an
MSVC C++ project. To build it, first replace `%NUGET_VERSION%` in
[packages.config](test/cpp/packages.config) with the version number you provided during the build.
Then, run:

```
cd test/cpp
nuget restore packages.config -PackagesDirectory .\packages
msbuild /p:NuGet_Version=<SymCrypt Package Version>
```

### Linux (.NET)

Linux consumption is supported for **.NET projects** that use `PackageReference` and set a
`RuntimeIdentifier`. The .NET SDK extracts `runtimes/<rid>/native/libsymcrypt.so` next to
the published output, and `[DllImport("symcrypt")]` resolves it.

Minimal example:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <RuntimeIdentifiers>linux-x64;linux-arm64</RuntimeIdentifiers>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.SymCrypt" Version="<SymCrypt Package Version>" />
  </ItemGroup>
</Project>
```

```csharp
using System.Runtime.InteropServices;

internal static class SymCrypt
{
    [DllImport("symcrypt")]
    public static extern void SymCryptSha256(byte[] data, nuint cbData, byte[] result);
}
```

Build with `dotnet publish -r linux-x64` (or `linux-arm64`).

#### Linux consumption caveats

- The package does not include a `libsymcrypt.so.<MAJOR>` SONAME symlink. If your
  runtime loader is configured to look up SymCrypt by SONAME, create the symlink as
  part of your publish step.
- Headers (`symcrypt.h`, `symcrypt_low_level.h`, `symcrypt_internal.h`,
  `symcrypt_internal_shared.inc`, `symcrypt_no_sal.h`) are placed in
  `lib/native/include/` inside the package. They are intended for C/C++ projects
  that consume the package via MSBuild on Windows; on Linux they are available but
  not wired into any build system.
- **Non-.NET Linux C/C++ builds are not supported by NuGet tooling.** If you need
  SymCrypt for a non-.NET Linux build, consume the Azure Linux binary distribution
  (`.tar.gz`) directly rather than going through NuGet.
- The Linux binaries shipped in this package come from the Azure Linux Clang Release
  build. They are byte-identical to the Linux binaries published from the same
  pipeline build, including the FIPS integrity hash.