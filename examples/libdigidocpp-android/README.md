# Build instructions for Android

### OSX

1. Install dependencies from
	* [http://www.cmake.org](http://www.cmake.org)
	* [http://swig.org](http://swig.org)

2. Prepare

        sh ../../prepare_osx_build_environment.sh [androidarm|androidarm64|androidx86] all

3. Build library

        sh build-library.sh [arm|arm64|x86]

4. Build example and run

        open project with Android Studio, build and run

Shared libraries must placed app/src/main/jniLibs/[armeabi-v7a,arm64-v8a,x86]/.
Also /Library/libdigidocpp.androidarm/etc/digidocpp/schema content should be ziped and included app/src/main/res/raw/schema.zip path.
It will be extracted on application execution and path given to library special digidoc.initializeLib(appName, path) JNI function.
