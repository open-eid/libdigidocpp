# libdigidocpp

![European Regional Development Fund](https://github.com/e-gov/RIHA-Frontend/raw/master/logo/EU/EU.png "European Regional Development Fund - DO NOT REMOVE THIS IMAGE BEFORE 05.03.2020")

 * License: LGPL 2.1
 * &copy; Estonian Information System Authority
 * [Architecture of ID-software](http://open-eid.github.io)

## Building
[![Build Status](https://github.com/open-eid/libdigidocpp/workflows/CI/badge.svg?branch=master)](https://github.com/open-eid/libdigidocpp/actions)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/727/badge.svg)](https://scan.coverity.com/projects/727)
[![LGTM alerts](https://img.shields.io/lgtm/alerts/g/open-eid/libdigidocpp.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/open-eid/libdigidocpp/alerts/)

### Ubuntu

1. Install dependencies

        sudo apt-get install cmake libxml-security-c-dev xsdcxx libssl-dev zlib1g-dev

	* doxygen - Optional, for API documentation
	* libboost-test-dev - Optional, for unittests

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

### macOS

1. Install dependencies from
	* [XCode](https://itunes.apple.com/en/app/xcode/id497799835?mt=12)
	* [http://www.cmake.org](http://www.cmake.org)

2. Fetch the source

        git clone --recursive https://github.com/open-eid/libdigidocpp
        cd libdigidocpp

3. Prepare dependencies (available targets: osx, ios, iossimulator, androidarm, androidarm64, androidx86)

        sh prepare_osx_build_environment.sh osx all

4. Configure, build and install (available targets: osx, ios, iossimulator, androidarm, androidarm64, androidx86)

        ./build-library.sh osx install

5. Execute

        /Library/libdigidocpp/bin/digidoc-tool

### Windows

1. Install dependencies and necessary tools from
	* [Visual Studio Community 2015/2017/2019](https://www.visualstudio.com/downloads/)
	* [CMake](http://www.cmake.org)
	* [7-zip](http://www.7-zip.org) - Optional, for prepare script
	* [Perl](https://www.perl.org/get.html) - Optional, for OpenSSL prepare script
	* [Swig](http://swig.org/download.html) - Optional, for C# bindings
	* [Wix toolset](http://wixtoolset.org/releases/) - Optional, for creating Windows installation packages

   Toolset:
        * 140 - Visual Studio 2015
        * 141 - Visual Studio 2017
        * 142 - Visual Studio 2019

2. Fetch the source

        git clone --recursive https://github.com/open-eid/libdigidocpp
        cd libdigidocpp

3. Prepare

        powershell -ExecutionPolicy ByPass -File prepare_win_build_environment.ps1 -toolset 140

4. Configure

        mkdir build
        cd build
        cmake ..

   Optional CMake parameters:

       -DSWIG_EXECUTABLE=C:/swigwin-4.0.1/swig.exe

   After running the cmake build, digidoc_csharp.dll along with the C# source files will be created, more info at
   [examples/DigiDocCSharp/README.md](examples/DigiDocCSharp/README.md).

5. Build

        nmake

6. Alternative to steps 4. and 5. -

        powershell -ExecutionPolicy ByPass -File build.ps1 -toolset 140

    The build script builds executables and installation media for all
    platforms (x86 and x64 / Debug and Release with debug symbols)

7. Execute

        src/digidoc-tool.exe

### Examples
[examples/README.md](examples/README.md)

## Support
Official builds are provided through official distribution point [id.ee](https://www.id.ee/en/article/install-id-software/). If you want support, you need to be using official builds. Contact our support via [www.id.ee](http://www.id.ee) for assistance.

Source code is provided on "as is" terms with no warranty (see license for more information). Do not file Github issues with generic support requests.
