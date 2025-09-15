# SymCrypt NuGet Package

This directory contains the NuGet package configuration for SymCrypt.

## Building the NuGet Package

Building the package manually is time-consuming and is not recommended, unless you have to make
changes to the package build process itself. Normally the package should be built from the
Azure DevOps pipeline; see [nuget-windows-undocked.yml](../.pipelines/templates/nuget-windows-undocked.yml)

1. Build SymCrypt for the target platforms supported by the NuGet package (currently Windows AMD64 and ARM64)
2. Use [package.py](../scripts/package.py) to package each build flavor.
3. Copy the package contents to their respective locations specified in symcrypt.nuspec:
   - AMD64: ../pkg/win-x64/
   - ARM64: ../pkg/win-arm64/
4. Create the package using the NuGet CLI, explicitly specifying the package version:
   ```
   nuget pack symcrypt.nuspec -Version <SymCrypt Package Version>
   ```

## Usage

The test project under the `test/cpp` directory shows how to consume the NuGet package from an
MSVC C++ project. To build it, first replace `%NUGET_VERSION%` in
[packages.config](test/cpp/packages.config) with the version number you provided during the build.
Then, run:

```
cd test/cpp
nuget restore packages.config -PackagesDirectory .\packages
msbuild /p:NuGet_Version=<SymCrypt Package Version>
```