# Build instructions for iOS

### macOS

1. Install the dependencies listed in the main [README](../../README.md#macos).
2. Set `VCPKG_ROOT`. The Xcode build invokes the matching `iphoneos`,
   `iphonesimulator` or `iphonecatalyst` CMake preset and builds libdigidocpp
   automatically.
3. Build the example and run it on a simulator:

        xcodebuild -project libdigidocpp.xcodeproj -sdk iphonesimulator

   Or open the Xcode project and run it on a simulator, device or Mac Catalyst
   target directly.

`DocumentViewModel.mm` shows how to override `digidoc::ConfCurrent` so TSL lists
use an application-writable cache directory.
