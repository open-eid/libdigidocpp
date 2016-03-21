# Build instructions for Android

### OSX

1. Install dependencies from
	* [Android NDK](https://developer.android.com/ndk/downloads/index.html)
	* [http://www.cmake.org](http://www.cmake.org)

2. Prepare

   xml-security-c 1.7.3 fails to build, because getcwd autotool configure test (1.7.2 works)
   
        export ANDROID_NDK=$HOME/android-ndk-r10e
        sh ../../prepare_osx_build_environment.sh android all

3. Build library, also needs libdigidoc dependency for DDoc support

        sh build-library.sh android

4. Build example and run

        open project with eclipse, build and run

Swig is required for generating digidoc_java.so for example JNI wrapper.

Shared library must placed libs/armeabi/libdigidoc_java.so. Also /Library/EstonianIDCard.android/etc/digidocpp/schema content should be ziped and included res/raw/schema.zip path. It will be extracted on application execution and path given to library special digidoc.initJava(path) JNI function.
Libdigidoc still needs adjusted to point CA files folder and include certificates in project.
