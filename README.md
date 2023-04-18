# libdigidocpp

![European Regional Development Fund](https://github.com/open-eid/DigiDoc4-Client/blob/master/client/images/EL_Regionaalarengu_Fond.png "European Regional Development Fund - DO NOT REMOVE THIS IMAGE BEFORE 05.03.2020")

 * License: LGPL 2.1
 * &copy; Estonian Information System Authority
 * [Architecture of ID-software](http://open-eid.github.io)

## Building
[![Build Status](https://github.com/open-eid/libdigidocpp/workflows/CI/badge.svg?branch=master)](https://github.com/open-eid/libdigidocpp/actions)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/727/badge.svg)](https://scan.coverity.com/projects/727)

### Ubuntu, Fedora

1. Install dependencies

        # Ubuntu
        sudo apt install cmake xxd libxml-security-c-dev xsdcxx libssl-dev zlib1g-dev
        # Fedora
        sudo dnf install cmake openssl-devel xerces-c-devel xml-security-c-devel zlib-devel vim-common https://www.codesynthesis.com/download/xsd/4.0/linux-gnu/x86_64/xsd-4.0.0-1.x86_64.rpm

	* doxygen - Optional, for API documentation
	* libboost-test-dev - Optional, for unittests
	* swig - Optional, for C#, Java and python bindings
	* libpython3-dev, python3-distutils - Optional, for python bindings
	* openjdk-8-jdk-headless - Optional, for Java bindings

2. Fetch the source

        git clone --recursive https://github.com/open-eid/libdigidocpp
        cd libdigidocpp

3. Configure

        cmake -B build -S .

4. Build

        cmake --build build

5. Install

        sudo cmake --build build --target install

6. Execute

        /usr/local/bin/digidoc-tool

### macOS

1. Install dependencies from
	* [XCode](https://itunes.apple.com/en/app/xcode/id497799835?mt=12)
	* [CMake](http://www.cmake.org)
	* [Homebrew](https://brew.sh)

2. Fetch the source

        git clone --recursive https://github.com/open-eid/libdigidocpp
        cd libdigidocpp

3. Prepare dependencies (available targets: osx, ios, iossimulator, androidarm, androidarm64, androidx86_64)

        sh prepare_osx_build_environment.sh osx all

4. Install dependencies

        brew install xsd
        brew unlink xerces-c

	* doxygen - Optional, for API documentation
	* boost - Optional, for unittests
	* swig - Optional, for C# and Java bindings
	* openjdk - Optional, for Java bindings

5. Configure, build and install (available targets: osx, ios, iossimulator, androidarm, androidarm64, androidx86_64)

        ./build-library.sh osx install

6. Execute

        /Library/Frameworks/digidocpp.framework/Resources/digidoc-tool

### Windows

1. Install dependencies and necessary tools from
	* [Visual Studio Community 2017/2019/2022](https://www.visualstudio.com/downloads/)
	* [CMake](http://www.cmake.org)
	* [Swig](http://swig.org/download.html) - Optional, for C# and Java bindings
	* [Doxygen](https://www.doxygen.nl/download.html) - Optional, for generationg documentation
	* [Wix toolset](http://wixtoolset.org/releases/) - Optional, for creating Windows installation packages
	* [Python](https://www.python.org/downloads/) - Optional, for Python bindings
	* [Java](https://www.oracle.com/java/technologies/downloads/) - Optional, for Java bindings

   Toolset:
	* 142 - Visual Studio 2019 (Default)
	* 143 - Visual Studio 2022

2. Fetch the source

        git clone --recursive https://github.com/open-eid/libdigidocpp
        cd libdigidocpp

3. Prepare

        powershell -ExecutionPolicy ByPass -File prepare_win_build_environment.ps1 -toolset 142

4. Configure

        cmake -DCMAKE_TOOLCHAIN_FILE=vcpkg/scripts/buildsystems/vcpkg.cmake" `
              -DVCPKG_TARGET_TRIPLET=x64-windows-v142 `
              -DXSD_INCLUDE_DIR=xsd/libxsd `
              -DXSD_EXECUTABLE=xsd/bin/xsd.exe `
              -B build -S .

   Optional CMake parameters:

       -DSWIG_EXECUTABLE=C:/swigwin-4.1.1/swig.exe

   After running the cmake build, digidoc_csharp.dll along with the C# source files will be created, more info at
   [examples/DigiDocCSharp/README.md](examples/DigiDocCSharp/README.md).

5. Build

        cmake --build build

6. Alternative to steps 4. and 5. -

        powershell -ExecutionPolicy ByPass -File build.ps1 -toolset 142

    The build script builds executables and installation media for all
    platforms (x86 and x64 / Debug and Release with debug symbols)

7. Execute

        build/src/digidoc-tool.exe

### Examples
[examples/README.md](examples/README.md)

## Support
Official builds are provided through official distribution point [id.ee](https://www.id.ee/en/article/install-id-software/). If you want support, you need to be using official builds. Contact our support via [www.id.ee](http://www.id.ee) for assistance.

Source code is provided on "as is" terms with no warranty (see license for more information). Do not file Github issues with generic support requests.
