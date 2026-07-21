# Build instructions for Android

### macOS

1. Install the dependencies listed in the main [README](../../README.md#macos).
2. Set `VCPKG_ROOT` and `ANDROID_NDK_ROOT`. The Gradle build invokes the
   `androidarm` and `androidarm64` CMake presets and installs their outputs into
   the example build directory automatically.
3. Build the example and install it on a connected device or emulator:

        ./gradlew installDebug
