param(
  [string]$target = "C:\build",
  [string]$msiversion = "3.13.3.0",
  [string]$msi_name = "libdigidocpp-$msiversion$env:VER_SUFFIX.msi",
  [string]$msbuild = "C:\Program Files (x86)\MSBuild\$Env:VisualStudioVersion\Bin\MSBuild.exe",
  [string]$cmake = "C:\Program Files (x86)\CMake\bin\cmake.exe",
  [string]$vcdir = "C:\Program Files (x86)\Microsoft Visual Studio $Env:VisualStudioVersion\VC",
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
  $cmakeext += "-DDOXYGEN_EXECUTABLE=$doxygen"
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
  New-Item -ItemType directory -Path source > $null
  Get-ChildItem -Path $libdigidocpp | % { Copy-Item $_.fullname source -Recurse -Force -Exclude build,doc,.git }
  & $heat dir source -nologo -cg Source -gg -scom -sreg -sfrag -srd -dr SourceFolder -var var.sourceLocation -out SourceFilesFragment.wxs
  $candleext += "-dsourceLocation=source", "SourceFilesFragment.wxs"
  $lightext += "SourceFilesFragment.wixobj"
}

foreach($platform in @("x86", "x64")) {
  foreach($type in @("Debug", "RelWithDebInfo")) {
    $buildpath = $platform+$type
    switch ($buildpath)
    { 'x86Debug' {
      $xerces_lib = 'x86/lib/xerces-c_3D.lib'
      $xerces_dll = 'x86/bin/xerces-c_3_2D.dll'
      $xerces_inc = 'x86/include'
      $xalanmsg_lib = 'Win32/VC10/Debug/XalanMsgLib.lib'
      $xalanmsg_dll = 'Win32/VC10/Debug/XalanMessages_1_11D.dll'
      $xalanc_lib = 'Win32/VC10/Debug/Xalan-C_1D.lib'
      $xalanc_dll = 'Win32/VC10/Debug/Xalan-C_1_11D.dll'
      $xmlsec_lib = 'Win32/VC12/Debug/xsec_1D.lib'
      $xmlsec_dll = 'Win32/VC12/Debug/xsec_1_7D.dll'
      $openssl = '/OpenSSL-Win32'
    } 'x86RelWithDebInfo' {
      $xerces_lib = 'x86/lib/xerces-c_3.lib'
      $xerces_dll = 'x86/bin/xerces-c_3_2.dll'
      $xerces_inc = 'x86/include'
      $xalanmsg_lib = 'Win32/VC10/Release/XalanMsgLib.lib'
      $xalanmsg_dll = 'Win32/VC10/Release/XalanMessages_1_11.dll'
      $xalanc_lib = 'Win32/VC10/Release/Xalan-C_1.lib'
      $xalanc_dll = 'Win32/VC10/Release/Xalan-C_1_11.dll'
      $xmlsec_lib = 'Win32/VC12/Release/xsec_1.lib'
      $xmlsec_dll = 'Win32/VC12/Release/xsec_1_7.dll'
      $openssl = '/OpenSSL-Win32'
    } 'x64Debug' {
      $xerces_lib = 'x64/lib/xerces-c_3D.lib'
      $xerces_dll = 'x64/bin/xerces-c_3_2D.dll'
      $xerces_inc = 'x86/include'
      $xalanmsg_lib = 'Win64/VC10/Debug/XalanMsgLib.lib'
      $xalanmsg_dll = 'Win64/VC10/Debug/XalanMessages_1_11D.dll'
      $xalanc_lib = 'Win64/VC10/Debug/Xalan-C_1D.lib'
      $xalanc_dll = 'Win64/VC10/Debug/Xalan-C_1_11D.dll'
      $xmlsec_lib = 'X64/VC12/Debug/xsec_1D.lib'
      $xmlsec_dll = 'X64/VC12/Debug/xsec_1_7D.dll'
      $openssl = '/OpenSSL-Win64'
    } 'x64RelWithDebInfo' {
      $xerces_lib = 'x64/lib/xerces-c_3.lib'
      $xerces_dll = 'x64/bin/xerces-c_3_2.dll'
      $xerces_inc = 'x86/include'
      $xalanmsg_lib = 'Win64/VC10/Release/XalanMsgLib.lib'
      $xalanmsg_dll = 'Win64/VC10/Release/XalanMessages_1_11.dll'
      $xalanc_lib = 'Win64/VC10/Release/Xalan-C_1.lib'
      $xalanc_dll = 'Win64/VC10/Release/Xalan-C_1_11.dll'
      $xmlsec_lib = 'X64/VC12/Release/xsec_1.lib'
      $xmlsec_dll = 'X64/VC12/Release/xsec_1_7.dll'
      $openssl = '/OpenSSL-Win64'
    }}
    if($libdigidoc) {
      $cmakeext += "-DLIBDIGIDOC_LIBRARY=$libdigidoc/$platform/bin/digidoc.lib"
      $cmakeext += "-DLIBDIGIDOC_INCLUDE_DIR=$libdigidoc/$platform/include"
    }
    Remove-Item $buildpath -Force -Recurse > $null
    New-Item -ItemType directory -Path $buildpath > $null
    Push-Location -Path $buildpath
    if($boost) {
      New-Item -ItemType directory -Path test > $null
      Copy-Item "$target/xerces/$xerces_dll" test
      Copy-Item "$target/xalan/c/Build/$xalanmsg_dll" test
      Copy-Item "$target/xalan/c/Build/$xalanc_dll" test
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
      "-DXERCESC_LIBRARY=$target/xerces/$xerces_lib" `
      "-DXERCESC_INCLUDE_DIR=$target/xerces/$xerces_inc" `
      "-DXALANC_INCLUDE_DIR=$target/xalan/c/src" `
      "-DXALANMSG_LIBRARY=$target/xalan/c/Build/$xalanmsg_lib" `
      "-DXALANC_LIBRARY=$target/xalan/c/Build/$xalanc_lib" `
      "-DXMLSECURITYC_LIBRARY=$target/xmlsec/Build/$xmlsec_lib" `
      "-DXMLSECURITYC_INCLUDE_DIR=$target/xmlsec" `
      "-DXSD_INCLUDE_DIR=$target/xsd/libxsd" `
      "-DXSD_EXECUTABLE=$target/xsd/bin/xsd.exe" `
      "-DZLIB_LIBRARY=$target/zlib/$platform/lib/zlib.lib" `
      "-DZLIB_INCLUDE_DIR=$target/zlib/$platform/include" `
      $cmakeext $libdigidocpp "&&" nmake /nologo install
    Pop-Location
  }
}

Function Sign($filename) {
  signtool.exe sign /a /v /s MY /n "$sign" /fd SHA256 /du http://installer.id.ee `
    /tr http://sha256timestamp.ws.symantec.com/sha256/timestamp /td SHA256 "$filename"
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
  $lightext libdigidocpp.wixobj HeadersFragment.wixobj
 
if($sign) {
  Sign($msi_name)
}
