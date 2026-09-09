# libdigidocpp

![European Regional Development Fund](https://github.com/open-eid/DigiDoc4-Client/blob/master/client/images/EL_Regionaalarengu_Fond.png "European Regional Development Fund - DO NOT REMOVE THIS IMAGE BEFORE 05.03.2020")

 * License: LGPL-2.1-or-later
 * &copy; Estonian Information System Authority
 * [Architecture of ID-software](https://open-eid.github.io)
 * [API Documentation](https://open-eid.github.io/libdigidocpp)

## Building
[![Build Status](https://github.com/open-eid/libdigidocpp/workflows/CI/badge.svg?branch=master)](https://github.com/open-eid/libdigidocpp/actions)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/727/badge.svg)](https://scan.coverity.com/projects/727)

### Ubuntu, Fedora

1. Install dependencies

        # Ubuntu
        sudo apt install cmake libxml2-dev libxmlsec1-dev zlib1g-dev
        # Fedora
        sudo dnf install cmake gcc-c++ libtool-ltdl-devel libxml2-devel minizip-ng-compat-devel openssl-devel zlib-devel xmlsec1-openssl-devel

	* doxygen - Optional, for API documentation
	* libboost-test-dev (Fedora: boost-devel) - Optional, for unittests
	* swig - Optional, for C#, Java and python bindings
	* libpython3-dev, python3-setuptools (Fedora: python3-devel, python3-setuptools) - Optional, for python bindings
	* openjdk-21-jdk-headless (Fedora: java-25-openjdk-devel) - Optional, for Java bindings

2. Fetch the source

        git clone https://github.com/open-eid/libdigidocpp
        cd libdigidocpp

3. List the available CMake presets and configure the default build

        cmake --list-presets
        cmake --preset default

4. Build

        cmake --build build/default

5. Install

        sudo cmake --build build/default --target install

6. Execute

        /usr/local/bin/digidoc-tool

### Ubuntu release packages

The Ubuntu packages published by RIA do not use the distribution's xmlsec.
They link a patched xmlsec 1.3 statically into libdigidocpp:

* xmlsec 1.2, shipped by Ubuntu 22.04 and 24.04, does not support SHA-3.
* [xmlsec1-1.3.12.legacy.patch](xmlsec1-1.3.12.legacy.patch) lets older RSA
  signatures validate when their PKCS#1 DigestInfo omits the NULL algorithm
  parameter.
* Static linking leaves the distribution's `libxmlsec1` package untouched for
  other software.

To build the same way:

1. Build and install xmlsec next to the libdigidocpp checkout

        sudo apt install build-essential
        curl -LO https://github.com/lsh123/xmlsec/releases/download/1.3.12/xmlsec1-1.3.12.tar.gz
        tar xf xmlsec1-1.3.12.tar.gz
        cd xmlsec1-1.3.12
        patch -Np1 -i ../libdigidocpp/xmlsec1-1.3.12.legacy.patch
        ./configure --prefix=/opt/xmlsec1-static \
          --disable-dependency-tracking \
          --disable-shared \
          --with-pic \
          --disable-crypto-dl \
          --disable-apps-crypto-dl \
          --without-gnutls \
          --without-gcrypt \
          --without-nss \
          --enable-openssl3-engines \
          --without-libltdl \
          --without-libxslt \
          --disable-apps \
          --enable-static-linking
        make
        sudo make install
        cd ..

2. Point pkg-config at it when configuring libdigidocpp, or when running
   `dpkg-buildpackage`

        cd libdigidocpp
        export PKG_CONFIG_PATH=/opt/xmlsec1-static/lib/pkgconfig
        cmake --preset default

### macOS

1. Install dependencies from
	* [XCode](https://itunes.apple.com/en/app/xcode/id497799835?mt=12) - For macOS/iOS development
	* [CMake](https://www.cmake.org)
	* [Homebrew](https://brew.sh)
	* [vcpkg](https://vcpkg.io/) - For iOS and Android development (`VCPKG_ROOT`)
	* [Android NDK](https://developer.android.com/ndk/downloads) - For Android development (ANDROID_NDK_ROOT)

2. Fetch the source

        git clone https://github.com/open-eid/libdigidocpp
        cd libdigidocpp

3. Prepare macOS dependencies

        sh prepare_osx_build_environment.sh all

   iOS and Android dependencies are managed by vcpkg instead. Set `VCPKG_ROOT`
   for both platforms and `ANDROID_NDK_ROOT` for Android before configuring.

4. Install dependencies

        brew install pkg-config ninja

	* doxygen - Optional, for API documentation
	* boost - Optional, for unittests
	* swig - Optional, for C#, Java and Python bindings
	* openjdk - Optional, for Java bindings

5. List the available presets, then configure, build and install. Platform presets
   include `macos`, `iphoneos`, `iphonesimulator`, `iphonecatalyst`,
   `androidarm`, `androidarm64` and `androidx86_64`.

        cmake --list-presets
        cmake --preset macos
        cmake --build --preset macos
        sudo cmake --build --preset macos --target install

6. Execute

        /Library/Frameworks/digidocpp.framework/Resources/digidoc-tool

### Windows

1. Install dependencies and necessary tools from
	* [Visual Studio](https://www.visualstudio.com/downloads/) with a supported MSVC toolset (v143 or v145)
	* [CMake](https://www.cmake.org)
	* [vcpkg](https://vcpkg.io/)
	* [Swig](https://swig.org/download.html) - Optional, for C#, Python and Java bindings
	* [Doxygen](https://www.doxygen.nl/download.html) - Optional, for generating documentation
	* [Wix toolset](https://wixtoolset.org/releases/) - Optional, for creating Windows installation packages
	* [Python](https://www.python.org/downloads/) - Optional, for Python bindings
	* [Java](https://www.oracle.com/java/technologies/downloads/) - Optional, for Java bindings

2. Open desired Visual Studio tools command prompt:
	* x64 Native Tool Command Prompt
	* x86 Native Tool Command Prompt
	* ARM64 Native Tool Command Prompt
	* Or some cross compile combination with target host type

3. Fetch the source

        git clone https://github.com/open-eid/libdigidocpp
        cd libdigidocpp

4. Set the target platform and vcpkg location, then configure with the checked-in
   Windows preset

        $env:PLATFORM = "x64"
        $env:VCPKG_ROOT = "C:/src/vcpkg"
        cmake --preset windows -DVCPKG_MANIFEST_FEATURES=tests

    Optional CMake parameters:

        -DSWIG_EXECUTABLE=C:/swigwin-4.4.1/swig.exe
        -DDOXYGEN_EXECUTABLE=C:/Program files/doxygen/bin/doxygen.exe

    After running the cmake build, digidoc_csharp.dll along with the C# source files will be created, more info at
    [examples/DigiDocCSharp/README.md](examples/DigiDocCSharp/README.md).

   The preset uses a platform-specific build directory such as
   `build/windows-x64`, keeping Windows builds separate from Linux, macOS and
   other Windows architectures.

5. Build

        cmake --build --preset windows --config RelWithDebInfo

6. Alternative to steps 4. and 5. -

        powershell -ExecutionPolicy ByPass -File build.ps1 -acceptWixEULA

    WiX 7 requires accepting its
    [Open Source Maintenance Fee EULA](https://docs.firegiant.com/wix/osmf/).
    Pass `-acceptWixEULA` only after reviewing the terms. The acceptance is stored
    for the current user, so the switch can be omitted from subsequent builds.

    Optional build.ps1 parameters:

        -swig C:/swigwin-4.4.1/swig.exe
        -doxygen "C:/Program files/doxygen/bin/doxygen.exe"
        -boost
        -acceptWixEULA

    The build script builds executables and installation media for given
    platform (Debug and Release with debug symbols)

7. Execute

        build/windows-x64/src/RelWithDebInfo/digidoc-tool.exe

### Examples
[examples/README.md](examples/README.md)

## Support
Official builds are provided through official distribution point [id.ee](https://www.id.ee/en/article/install-id-software/). If you want support, you need to be using official builds. Contact our support via [www.id.ee](https://www.id.ee) for assistance.

Source code is provided on "as is" terms with no warranty (see license for more information). Do not file Github issues with generic support requests.
