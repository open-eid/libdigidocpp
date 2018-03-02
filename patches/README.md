# Android patches
* iconv.c.patch - arm64
* MsgCreator - macOS prebuild binary for Xalan-C cross compiling
* xmlsec.patch - Workaround missing android sdk elements

# iOS patches
* MsgCreator - macOS prebuild binary for Xalan-C cross compiling
* xalan-CMakeLists.txt - Xalan-C cmake project for static build

# Windows patches
* xerces-char16_t.patch - Xalan-C build fixes with VS2015 and xerces-c 3.2.0
  https://issues.apache.org/jira/browse/XALANC-773
* xml-security-c-1.7.3-VC12.zip - Updated VS project files

# Linux patches
* xml-security-c-1.7.3_openssl1.1.patch - Fedora ships openssl 1.1

# Experimental patches to build library on WinRT platform
* build openssl from Microsoft fork https://github.com/microsoft/openssl
* build Xerces-C and Xml-Security-C with applied patches
