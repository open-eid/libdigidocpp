# Build instructions for Android

### macOS

1. Install dependencies see [README.md](../../README.md#macOS)
2. Build example and run

        open project with Android Studio, build and run

Shared libraries must placed app/src/main/jniLibs/[armeabi-v7a,arm64-v8a,x86]/.
Also /Library/libdigidocpp.androidarm/etc/digidocpp/schema content should be ziped and included app/src/main/res/raw/schema.zip path.
It will be extracted on application execution and path given to library special digidoc.initializeLib(appName, path) JNI function.
