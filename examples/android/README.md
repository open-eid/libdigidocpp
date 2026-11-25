# Build instructions for Android

### macOS

1. Install the dependencies listed in the main [README](../../README.md#macos).
2. Set `VCPKG_ROOT` and `ANDROID_NDK_ROOT`. The Gradle build invokes the
   `androidarm` and `androidarm64` CMake presets and installs their outputs into
   the example build directory automatically. Instead of environment variables,
   which Android Studio does not inherit from the shell, `local.properties` can
   set `vcpkg.root` and, optionally, `ndk.root`. Without `ndk.root`,
   `ANDROID_NDK_HOME` or `ANDROID_NDK_ROOT`, the build uses the newest NDK under
   `sdk.dir`.
3. Build the example and install it on a connected device or emulator:

        ./gradlew installDebug

The app is written in Kotlin with Jetpack Compose. It opens a signed document
chosen with **Open document**, validates it, and lists its data files and
signatures.
