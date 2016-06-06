# libdigidocpp

 * License: LGPL 2.1
 * &copy; Estonian Information System Authority
 * [Architecture of ID-software](http://open-eid.github.io)

## Building
[![Build Status](https://travis-ci.org/open-eid/libdigidocpp.svg?branch=master)](https://travis-ci.org/open-eid/libdigidocpp)
[![Build Status](https://ci.appveyor.com/api/projects/status/github/open-eid/libdigidocpp?branch=master&svg=true)](https://ci.appveyor.com/project/open-eid/libdigidocpp)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/727/badge.svg)](https://scan.coverity.com/projects/727)

### Ubuntu

1. Install dependencies

        sudo apt-get install cmake libxml-security-c-dev xsdcxx libssl-dev

2. Fetch the source

        git clone --recursive https://github.com/open-eid/libdigidocpp
        cd libdigidocpp

3. Configure

        mkdir build
        cd build
        cmake ..

4. Build

        make

5. Install

        sudo make install

6. Execute

        /usr/local/bin/digidoc-tool

### OSX

1. Install dependencies from
	* [XCode](https://itunes.apple.com/en/app/xcode/id497799835?mt=12)
	* [http://www.cmake.org](http://www.cmake.org)

2. Fetch the source

        git clone --recursive https://github.com/open-eid/libdigidocpp
        cd libdigidocpp

3. Prepare

        sh prepare_osx_build_environment.sh all

4. Configure

        mkdir build
        cd build
        cmake ..

5. Build

        make

6. Install

        sudo make install

7. Execute

        /usr/local/bin/digidoc-tool

### Windows

1. Install dependencies and necessary tools from
	* [Visual Studio Express 2013 for Windows Desktop](http://www.visualstudio.com/en-us/products/visual-studio-express-vs.aspx)
	* [Perl] (https://www.perl.org/get.html)
	* [7-zip] (http://www.7-zip.org)
	* [http://www.cmake.org](http://www.cmake.org)
	* [Xerces-c](http://mirror.cogentco.com/pub/apache//xerces/c/3/sources/xerces-c-3.1.1.zip)
	* [Xerces-c MSVC2012 Project files](https://issues.apache.org/jira/secure/attachment/12548623/xerces_vc11proj.zip)
	* [XML-Security-C](http://www.apache.org/dyn/closer.cgi?path=/santuario/c-library/xml-security-c-1.7.2.tar.gz)
	* [OpenSSL Win32 binaries](https://slproweb.com/products/Win32OpenSSL.html) or [OpenSSL source](https://www.openssl.org/source/)
	* [ZLib source](http://zlib.net/zlib128.zip)
	* [swigwin-3.0.5.zip](http://swig.org/download.html) - Optional, for C# bindings

2. Fetch the source

        git clone --recursive https://github.com/open-eid/libdigidocpp
        cd libdigidocpp

3. Prepare

        powershell -ExecutionPolicy ByPass -File prepare_win_build_environment.ps1

4. Configure

        mkdir build
        cd build
        cmake ..

   Optional CMake parameters:

       -DSWIG_EXECUTABLE=C:/swigwin-3.0.5/swig.exe

   After running the cmake build, digidoc_csharp.dll along with the C# source files will be created, more info at
   [README.md](https://github.com/open-eid/libdigidocpp/blob/master/examples/DigiDocCSharp/README.md).


5. Build

        make

6. Execute

        src/digidoc-tool.exe

## Support
Official builds are provided through official distribution point [installer.id.ee](https://installer.id.ee). If you want support, you need to be using official builds. Contact for assistance by email [abi@id.ee](mailto:abi@id.ee) or [www.id.ee](http://www.id.ee).

Source code is provided on "as is" terms with no warranty (see license for more information). Do not file Github issues with generic support requests.
