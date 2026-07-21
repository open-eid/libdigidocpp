# C# example

The C# bindings are generated with [SWIG](https://www.swig.org/) and work on
Windows, macOS and Linux. The example targets .NET 8.

## Prerequisites

Install the native build dependencies for your platform from the main
[build instructions](../../README.md), together with SWIG and the .NET 8 SDK or
newer.

## Build the native wrapper

On Linux, use the default preset:

    cmake --preset default
    cmake --build build/default --target digidoc_csharp

On macOS, use the macOS preset:

    cmake --preset macos
    cmake --build --preset macos --target digidoc_csharp

On Windows, use a Visual Studio tools PowerShell and the Windows preset:

    $env:PLATFORM = "x64"
    $env:VCPKG_ROOT = "C:/src/vcpkg"
    cmake --preset windows -DSWIG_EXECUTABLE=C:/swigwin/swig.exe
    cmake --build --preset windows --config RelWithDebInfo --target digidoc_csharp

The generated C# files are written to the `src/csharp` directory inside the
selected CMake build directory—for example, `build/default/src/csharp`,
`build/macos/src/csharp` or `build/windows-x64/src/csharp`. Copy or add those
`.cs` files to the example's `digidoc` folder, then build the managed project:

    dotnet build examples/DigiDocCSharp/DigiDocCSharp.csproj -c Release

Before running the example, make the directory containing the native
libdigidocpp and SWIG wrapper libraries available to the platform loader:

- Windows: add it to `PATH`.
- macOS: add it to `DYLD_LIBRARY_PATH`.
- Linux: add it to `LD_LIBRARY_PATH`.

Use native libraries matching the process architecture and build configuration.
Installing libdigidocpp is an alternative to setting a build-tree loader path.

## Example commands

Use `DigiDocCSharp.exe` on Windows or `dotnet DigiDocCSharp.dll` on macOS and
Linux. For example:

    dotnet DigiDocCSharp.dll version
    dotnet DigiDocCSharp.dll help
    dotnet DigiDocCSharp.dll add text.txt unsigned.asice
    dotnet DigiDocCSharp.dll verify signed.asice
    dotnet DigiDocCSharp.dll extract 0 signed.asice

Signing uses `WinSigner` on Windows. On macOS and Linux it uses `PKCS11Signer`,
so the PIN precedes the input file arguments:

    dotnet DigiDocCSharp.dll sign 12345 text.txt signed.asice

The C# API mirrors the public libdigidocpp API. See the generated bindings and
the [libdigidocpp API documentation](https://open-eid.github.io/libdigidocpp/)
for the available classes and methods.
