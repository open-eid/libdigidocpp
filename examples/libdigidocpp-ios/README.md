# Build instructions for iOS

### OSX

1. Install dependencies from
	* [XCode](https://itunes.apple.com/en/app/xcode/id497799835?mt=12)
	* [http://www.cmake.org](http://www.cmake.org)

2. Prepare

   xml-security-c 1.7.3 fails to build, because getcwd autotool configure test (1.7.2 works, requires modifing prepare_osx_build_environment.sh script)
   
        sh ../../prepare_osx_build_environment.sh ios all
        sh ../../prepare_osx_build_environment.sh simulator all

3. Build library, also needs libdigidoc dependency for DDoc support

        sh build-library.sh ios
        sh build-library.sh simulator

4. Build example

        xcodebuild -project libdigidocpp-ios.xcodeproj

5. Execute

        Open Xcode project and run on simulator


AppDelegate.mm contains how to override digidoc::XmlConf to point right cache folder for TSL lists and XSD schema folders. Project also includes schema folder (/Library/EstonianIDCard.iphoneos/etc/digidocpp/schema).
Libdigidoc still needs adjusted to point CA files folder and include certificates in project.
