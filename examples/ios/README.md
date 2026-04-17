# Build instructions for iOS

### macOS

1. Install dependencies see [README.md](../../README.md#macOS)
2. Build example and run on simulator

        xcodebuild -project libdigidocpp.xcodeproj -sdk iphonesimulator

   Or open the Xcode project and run on a simulator or device directly.

AppDelegate.mm contains how to override digidoc::XmlConf to point right cache folder for TSL lists.
