param(
  [string]$target = "C:\build",
  [string]$msiversion = "3.12.0.0",
  [string]$msi_name = "libdigidocpp-$msiversion$env:VER_SUFFIX.msi",
  [string]$msbuild = "C:\Program Files (x86)\MSBuild\12.0\Bin\MSBuild.exe",
  [string]$cmake = "C:\Program Files (x86)\CMake\bin\cmake.exe",
  [string]$vcdir = "C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC",
  [string]$heat = "$env:WIX\bin\heat.exe",
  [string]$candle = "$env:WIX\bin\candle.exe",
  [string]$light = "$env:WIX\bin\light.exe",
  [string]$swig = $null,
  [string]$doxygen = $null,
  [string]$libdigidoc = $null,
  [string]$boost = $null,
  [string]$sign = $null,
  [switch]$source = $false
)

$libdigidocpp = split-path -parent $MyInvocation.MyCommand.Definition
$cmakeext = @()
$candleext = @()
$lightext = @()
if($swig) {
  $cmakeext += "-DSWIG_EXECUTABLE=$swig"
  $candleext += "-dswig=$swig"
}
if($doxygen) {
  $cmakeext += "-DINSTALL_DOC=YES", "-DDOXYGEN_EXECUTABLE=$doxygen"
  $candleext += "-ddocLocation=x86/share/doc/libdigidocpp", "DocFilesFragment.wxs"
  $lightext += "DocFilesFragment.wixobj"
}
if($libdigidoc) {
  & $heat dir $libdigidoc/x86/share/libdigidoc -nologo -cg Certs -gg -scom -sreg -sfrag -srd -dr CertsFolder -var var.certsLocation -out CertsFragment.wxs
  $candleext += "-dcertsLocation=$libdigidoc/x86/share/libdigidoc", "-dlibdigidoc=$libdigidoc", "CertsFragment.wxs"
  $lightext += "CertsFragment.wixobj"
}
if($boost) {
  $cmakeext += "-DBoost_INCLUDE_DIR=$boost"
}
if($source) {
  Remove-Item source -Force -Recurse
  New-Item -ItemType directory -Path source
  Get-ChildItem -Path $libdigidocpp | % { Copy-Item $_.fullname source -Recurse -Force -Exclude build,doc,.git }
  & $heat dir source -nologo -cg Source -gg -scom -sreg -sfrag -srd -dr SourceFolder -var var.sourceLocation -out SourceFilesFragment.wxs
  $candleext += "-dsourceLocation=source", "SourceFilesFragment.wxs"
  $lightext += "SourceFilesFragment.wixobj"
}

Remove-Item build -Force -Recurse
foreach($platform in @("x86", "x64")) {
  foreach($type in @("Debug", "RelWithDebInfo")) {
    switch ($platform+$type)
    { 'x86Debug' {
      $xerces_lib = 'Win32/VC12/Debug/xerces-c_3D.lib'
      $xerces_dll = 'Win32/VC12/Debug/xerces-c_3_1D.dll'
      $xmlsec_lib = 'Win32/VC12/Debug No Xalan/xsec_1D.lib'
      $xmlsec_dll = 'Win32/VC12/Debug No Xalan/xsec_1_7D.dll'
      $openssl = '/OpenSSL-Win32'
    } 'x86RelWithDebInfo' {
      $xerces_lib = 'Win32/VC12/Release/xerces-c_3.lib'
      $xerces_dll = 'Win32/VC12/Release/xerces-c_3_1.dll'
      $xmlsec_lib = 'Win32/VC12/Release No Xalan/xsec_1.lib'
      $xmlsec_dll = 'Win32/VC12/Release No Xalan/xsec_1_7.dll'
      $openssl = '/OpenSSL-Win32'
    } 'x64Debug' {
      $xerces_lib = 'Win64/VC12/Debug/xerces-c_3D.lib'
      $xerces_dll = 'Win64/VC12/Debug/xerces-c_3_1D.dll'
      $xmlsec_lib = 'X64/VC12/Debug No Xalan/xsec_1D.lib'
      $xmlsec_dll = 'X64/VC12/Debug No Xalan/xsec_1_7D.dll'
      $openssl = '/OpenSSL-Win64'
    } 'x64RelWithDebInfo' {
      $xerces_lib = 'Win64/VC12/Release/xerces-c_3.lib'
      $xerces_dll = 'Win64/VC12/Release/xerces-c_3_1.dll'
      $xmlsec_lib = 'X64/VC12/Release No Xalan/xsec_1.lib'
      $xmlsec_dll = 'X64/VC12/Release No Xalan/xsec_1_7.dll'
      $openssl = '/OpenSSL-Win64'
    }}
    if($libdigidoc) {
      $cmakeext += "-DLIBDIGIDOC_LIBRARY=$libdigidoc/$platform/bin/digidoc.lib"
      $cmakeext += "-DLIBDIGIDOC_INCLUDE_DIR=$libdigidoc/$platform/include"
    }
    New-Item -ItemType directory -Path build
    Push-Location -Path build
    if($boost) {
      New-Item -ItemType directory -Path test
      Copy-Item "$target/xerces/Build/$xerces_dll" test
      Copy-Item "$target/xmlsec/Build/$xmlsec_dll" test
      Copy-Item "$target/zlib/$platform/bin/zlib1.dll" test
      Copy-Item "$openssl/bin/ssleay32.dll" test
      Copy-Item "$openssl/bin/libeay32.dll" test
      if($libdigidoc) {
        Copy-Item "$libdigidoc/$platform/bin/digidoc.dll" test
        Copy-Item "$target/libxml2/$platform/bin/libxml2.dll" test
      }
    }
    & $vcdir\vcvarsall.bat $platform "&&" $cmake "-GNMake Makefiles" "-DCMAKE_BUILD_TYPE=$type" "-DCMAKE_INSTALL_PREFIX=../$platform" "-DCMAKE_INSTALL_LIBDIR=bin" `
      "-DOPENSSL_ROOT_DIR=$openssl" `
      "-DXERCESC_LIBRARY=$target/xerces/Build/$xerces_lib" `
      "-DXERCESC_INCLUDE_DIR=$target/xerces/src" `
      "-DXMLSECURITYC_LIBRARY=$target/xmlsec/Build/$xmlsec_lib" `
      "-DXMLSECURITYC_INCLUDE_DIR=$target/xmlsec" `
      "-DXSD_INCLUDE_DIR=$target/xsd/libxsd" `
      "-DXSD_EXECUTABLE=$target/xsd/bin/xsd.exe" `
      "-DZLIB_LIBRARY=$target/zlib/$platform/lib/zlib.lib" `
      "-DZLIB_INCLUDE_DIR=$target/zlib/$platform/include" `
      $cmakeext $libdigidocpp "&&" nmake install
    Pop-Location
    Remove-Item build -Force -Recurse
  }
}

Function Sign($filename) {
  signtool.exe sign /a /v /s MY /n "$sign" /fd SHA256 /du http://installer.id.ee `
    /t http://timestamp.verisign.com/scripts/timstamp.dll "$filename"
}

if($sign) {
  Sign("x86\bin\*.dll")
  Sign("x86\bin\*.exe")
  Sign("x64\bin\*.dll")
  Sign("x64\bin\*.exe")
}

if($doxygen) {
  & $heat dir x86/share/doc/libdigidocpp -nologo -cg Documentation -gg -scom -sreg -sfrag -srd -dr DocumentationFolder -var var.docLocation -out DocFilesFragment.wxs
}
& $heat dir x86/include -nologo -cg Headers -gg -scom -sreg -sfrag -srd -dr HeadersFolder -var var.headersLocation -out HeadersFragment.wxs
& $candle -nologo "-dICON=$libdigidocpp/cmake/modules/ID.ico" "-dMSI_VERSION=$msiversion" "-dPREFIX=$target" `
  "-dVCINSTALLDIR=$vcdir" "-dheadersLocation=x86/include" "-dlibdigidocpp=." $candleext `
  $libdigidocpp\libdigidocpp.wxs HeadersFragment.wxs
& $light -nologo -out $msi_name -ext WixUIExtension `
  "-dWixUIBannerBmp=$libdigidocpp/cmake/modules/banner.bmp" `
  "-dWixUIDialogBmp=$libdigidocpp/cmake/modules/dlgbmp.bmp" `
  "-dWixUILicenseRtf=$libdigidocpp/cmake/modules/LICENSE.LGPL.rtf" $lightext `
  libdigidocpp.wixobj HeadersFragment.wixobj
 
if($sign) {
  Sign($msi_name)
}