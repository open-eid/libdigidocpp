## C-SHARP
Uses [http://swig.org/](http://swig.org/) tools for generating bindings. 

## Setting up the sample C# application

For compiling and running the DigiDocCSharp sample C# project, do as follows:

1. Install the "libdigidocpp-3.14.4.msi" package or higher. The installation packages are available from https://github.com/open-eid/libdigidocpp/releases
2. Open the C# sample project from source\examples\DigiDocCSharp folder located in the installation directory
3. Add the C# source files files from include\digidocpp_csharp folder to the digidoc folder of the opened project (in Solution Explorer view, right click on the digidoc folder, choose Add->Existing item)
4. Build the solution, DigiDocCSharp.exe executable is created
4. Libdigidocpp library's binaries (in the x64 or x86 folder of the "libdigidocpp" package's installation directory) need to be accessible for running the DigiDocCSharp executable. You can either copy the DigiDocCSharp.exe to the x64 or x86 folder, depending on the platform or set the working directory of the project accordingly or add the binaries' folder to PATH variable.
5. Run the DigiDocCSharp.exe sample program with the commands described in the next section

## Commands of the sample application Program.cs
* DigiDocCSharp.exe version
* DigiDocCSharp.exe help
* DigiDocCSharp.exe verify test.bdoc
* DigiDocCSharp.exe sign text.txt test.bdoc
* DigiDocCSharp.exe extract=0 test.bdoc

## API
* [digidoc.initialize()](http://open-eid.github.io/libdigidocpp/namespacedigidoc.html#ada31d19121d7a6d98b04267f3ed8cc8f)
* [Container](http://open-eid.github.io/libdigidocpp/classdigidoc_1_1Container.html)
* [DataFile](http://open-eid.github.io/libdigidocpp/classdigidoc_1_1DataFile.html)
* [Signature](http://open-eid.github.io/libdigidocpp/classdigidoc_1_1Signature.html)
* [digidoc.terminate()](http://open-eid.github.io/libdigidocpp/namespacedigidoc.html#a121f0363627f62f3972ac4b445986598)
