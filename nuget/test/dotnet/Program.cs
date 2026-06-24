// Layout-validation stub for the Microsoft.SymCrypt NuGet package's Linux runtime
// assets. This program is *not* intended to execute -- it is only used as a target
// for `dotnet publish -r linux-x64` and `-r linux-arm64` in the build pipeline to
// confirm that libsymcrypt.so is correctly placed in the publish output for each
// Linux RID. The P/Invoke declaration below ensures the publish RID actually
// requires the native asset; if SymCrypt's runtimes/<rid>/native/ layout breaks,
// the .so will not be copied into the publish folder and the pipeline assertion
// will fail.

using System.Runtime.InteropServices;

namespace SymCryptNuGetLinuxTest;

internal static class Program
{
    [DllImport("symcrypt")]
    private static extern void SymCryptSha256(byte[] pbData, nuint cbData, byte[] pbResult);

    public static int Main()
    {
        Console.WriteLine("SymCrypt NuGet Linux layout test stub (not intended to run).");
        return 0;
    }
}
