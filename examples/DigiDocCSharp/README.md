## C-SHARP
Kasutab [http://swig.org/](http://swig.org/) vahendeid bindingu genereerimise jaoks.

Alla tuleb laadida [swigwin-3.0.5.zip](http://swig.org/download.html)

Teegi ehitamise juhise leiab [https://github.com/open-eid/libdigidocpp/blob/master/README.md](README.md) kus tuleb lisaks määrata cmake build parameeter

    -DSWIG_EXECUTABLE=C:/swigwin-3.0.5/swig.exe'

Millega ehitatakse digidoc_csharp.dll ja PInvoke jaoks failid swig/csharp kataloogi, mis tuleb importida C# projekti.

Binaarsel kujul olev dll on sadaval
[https://github.com/open-eid/libdigidocpp/releases/tag/v3.10.3-beta](installi pakis)

## API
* [digidoc.initialize()](http://open-eid.github.io/libdigidocpp/namespacedigidoc.html#ada31d19121d7a6d98b04267f3ed8cc8f)
* [Container](http://open-eid.github.io/libdigidocpp/classdigidoc_1_1Container.html)
* [DataFile](http://open-eid.github.io/libdigidocpp/classdigidoc_1_1DataFile.html)
* [Signature](http://open-eid.github.io/libdigidocpp/classdigidoc_1_1Signature.html)
* [digidoc.terminate()](http://open-eid.github.io/libdigidocpp/namespacedigidoc.html#a121f0363627f62f3972ac4b445986598)

## Näidisrakenduse Program.cs käsud
* DigiDocCSharp.exe -version
* DigiDocCSharp.exe -help
* DigiDocCSharp.exe -verify test.bdoc
* DigiDocCSharp.exe -sign text.txt test.bdoc
* DigiDocCSharp.exe -extract=0 test.bdoc
