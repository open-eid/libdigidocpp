# Build instructions for iOS

### macOS

1. Install dependencies see [README.md](../../README.md#macOS)
2. Build example

        xcodebuild -project libdigidocpp.xcodeproj

3. Execute

        Open Xcode project and run on simulator


AppDelegate.mm contains how to override digidoc::XmlConf to point right cache folder for TSL lists.
