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

        sudo apt-get install cmake libxml-security-c-dev xsdcxx libssl-dev doxygen libxerces-c-dev swig libboost-dev

2. Fetch the source

        git clone --recursive https://github.com/open-eid/libdigidocpp
        cd libdigidocpp

3. Configure

        mkdir build
        cd build
        cmake ..

   if you are seeing 'include could not find load file: VersionInfo',
   you didn't do a recursive clone in the previous step.

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
	* [Perl](https://www.perl.org/get.html)
	* [7-zip](http://www.7-zip.org)
	* [http://www.cmake.org](http://www.cmake.org) - NB! Build scripts use 32-bit version of CMake
	* [swigwin-3.0.10.zip](http://swig.org/download.html) - Optional, for C# bindings
	* [Wix toolset](http://wixtoolset.org/releases/) - Optional, for creating Windows installation packages

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

       -DSWIG_EXECUTABLE=C:/swigwin-3.0.10/swig.exe

   After running the cmake build, digidoc_csharp.dll along with the C# source files will be created, more info at
   [examples/DigiDocCSharp/README.md](examples/DigiDocCSharp/README.md).

5. Build

        nmake

6. Alternative to steps 4. and 5. -

        Run the build script in PowerShell:
        ./build.ps1

    The build script builds executables and installation media for all
    platforms (x86 and x64 / Debug and Release with debug symbols)

7. Execute

        src/digidoc-tool.exe

### iOS Experimental
[examples/libdigidocpp-ios/README.md](examples/libdigidocpp-ios/README.md)

### Android Experimental
[examples/libdigidocpp-android/README.md](examples/libdigidocpp-android/README.md)

## Support
Official builds are provided through official distribution point [installer.id.ee](https://installer.id.ee). If you want support, you need to be using official builds. Contact for assistance by email [abi@id.ee](mailto:abi@id.ee) or [www.id.ee](http://www.id.ee).

Source code is provided on "as is" terms with no warranty (see license for more information). Do not file Github issues with generic support requests.
