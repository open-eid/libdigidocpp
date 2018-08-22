# Android patches
* iconv.c.patch - arm64
* MsgCreator - macOS prebuild binary for Xalan-C cross compiling

# iOS patches
* MsgCreator - macOS prebuild binary for Xalan-C cross compiling
* xalan-CMakeLists.txt - Xalan-C cmake project for static build

# Windows patches
* xalan-winproj.patch - Xalan-C Visual Studio project fixes
* xerces-char16_t.patch - Xalan-C build fixes with VS2015 and xerces-c 3.2.0
  https://issues.apache.org/jira/browse/XALANC-773
* xml-security-c-2.0.1-win.patch - Updated VS project files

# Experimental patches to build library on WinRT platform
* build openssl from Microsoft fork https://github.com/microsoft/openssl
* build Xerces-C and Xml-Security-C with applied patches
