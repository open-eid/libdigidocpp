param(
  [string]$target = "\build",
  [string]$buildver = "0",
  [string]$msiversion = "3.14.6.$buildver",
  [string]$msi_name = "libdigidocpp-$msiversion$env:VER_SUFFIX.msi",
  [string]$cmake = "cmake.exe",
  [string]$nmake = "nmake.exe",
  [string]$generator = "NMake Makefiles",
  [string]$toolset = "141",
  [string]$vcvars = $null,
  [string]$heat = "$env:WIX\bin\heat.exe",
  [string]$candle = "$env:WIX\bin\candle.exe",
  [string]$light = "$env:WIX\bin\light.exe",
  [string]$swig = $null,
  [string]$doxygen = $null,
  [string]$libdigidoc = $null,
  [string]$boost = $null,
  [string]$sign = $null,
  [string]$crosssign = $null,
  [switch]$source = $false
)

if (!$vcvars) {
	switch ($toolset) {
	'140' { $vcvars = "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" }
	'141' { $vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat" }
	'142' { $vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" }
	}
}

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
      $xerces_dll = 'xerces-c_3_2D.dll'
      $xalanmsg_lib = 'Win32/VC10/Debug/XalanMsgLib.lib'
      $xalanmsg_dll = 'Win32/VC10/Debug/XalanMessages_1_11D.dll'
      $xalanc_lib = 'Win32/VC10/Debug/Xalan-C_1D.lib'
      $xalanc_dll = 'Win32/VC10/Debug/Xalan-C_1_11D.dll'
      $xmlsec_lib = 'Win32/VC15/Debug/xsec_2D.lib'
      $xmlsec_dll = 'Win32/VC15/Debug/xsec_2_0D.dll'
      $openssl = '/OpenSSL-Win32'
      $openssl_dll = ''
    } 'x86RelWithDebInfo' {
      $xerces_dll = 'xerces-c_3_2.dll'
      $xalanmsg_lib = 'Win32/VC10/Release/XalanMsgLib.lib'
      $xalanmsg_dll = 'Win32/VC10/Release/XalanMessages_1_11.dll'
      $xalanc_lib = 'Win32/VC10/Release/Xalan-C_1.lib'
      $xalanc_dll = 'Win32/VC10/Release/Xalan-C_1_11.dll'
      $xmlsec_lib = 'Win32/VC15/Release/xsec_2.lib'
      $xmlsec_dll = 'Win32/VC15/Release/xsec_2_0.dll'
      $openssl = '/OpenSSL-Win32'
      $openssl_dll = ''
    } 'x64Debug' {
      $xerces_dll = 'xerces-c_3_2D.dll'
      $xalanmsg_lib = 'Win64/VC10/Debug/XalanMsgLib.lib'
      $xalanmsg_dll = 'Win64/VC10/Debug/XalanMessages_1_11D.dll'
      $xalanc_lib = 'Win64/VC10/Debug/Xalan-C_1D.lib'
      $xalanc_dll = 'Win64/VC10/Debug/Xalan-C_1_11D.dll'
      $xmlsec_lib = 'X64/VC15/Debug/xsec_2D.lib'
      $xmlsec_dll = 'X64/VC15/Debug/xsec_2_0D.dll'
      $openssl = '/OpenSSL-Win64'
      $openssl_dll = '-x64'
    } 'x64RelWithDebInfo' {
      $xerces_dll = 'xerces-c_3_2.dll'
      $xalanmsg_lib = 'Win64/VC10/Release/XalanMsgLib.lib'
      $xalanmsg_dll = 'Win64/VC10/Release/XalanMessages_1_11.dll'
      $xalanc_lib = 'Win64/VC10/Release/Xalan-C_1.lib'
      $xalanc_dll = 'Win64/VC10/Release/Xalan-C_1_11.dll'
      $xmlsec_lib = 'X64/VC15/Release/xsec_2.lib'
      $xmlsec_dll = 'X64/VC15/Release/xsec_2_0.dll'
      $openssl = '/OpenSSL-Win64'
      $openssl_dll = '-x64'
    }}
    if($libdigidoc) {
      $cmakeext += "-DLIBDIGIDOC_LIBRARY=$libdigidoc/$platform/bin/digidoc.lib"
      $cmakeext += "-DLIBDIGIDOC_INCLUDE_DIR=$libdigidoc/$platform/include"
    }
    Remove-Item $buildpath -Force -Recurse -ErrorAction Ignore
    New-Item -ItemType directory -Path $buildpath > $null
    Push-Location -Path $buildpath
    if($boost) {
      New-Item -ItemType directory -Path test > $null
      Copy-Item "$target/xerces/$platform/bin/$xerces_dll" test
      Copy-Item "$target/xalan/c/Build/$xalanmsg_dll" test
      Copy-Item "$target/xalan/c/Build/$xalanc_dll" test
      Copy-Item "$target/xmlsec/Build/$xmlsec_dll" test
      Copy-Item "$target/zlib/$platform/bin/zlib1.dll" test
      Copy-Item "$openssl/bin/libssl-1_1$openssl_dll.dll" test
      Copy-Item "$openssl/bin/libcrypto-1_1$openssl_dll.dll" test
      if($libdigidoc) {
        Copy-Item "$libdigidoc/$platform/bin/digidoc.dll" test
        Copy-Item "$target/libxml2/$platform/bin/libxml2.dll" test
      }
    }
    & $vcvars $platform "&&" $cmake "-G$generator" "-DCMAKE_BUILD_TYPE=$type" "-DCMAKE_INSTALL_PREFIX=../$platform" "-DCMAKE_INSTALL_LIBDIR=bin" `
      "-DOPENSSL_ROOT_DIR=$openssl" `
      "-DXercesC_ROOT=$target/xerces/$platform" `
      "-DXALANC_INCLUDE_DIR=$target/xalan/c/src" `
      "-DXALANMSG_LIBRARY=$target/xalan/c/Build/$xalanmsg_lib" `
      "-DXALANC_LIBRARY=$target/xalan/c/Build/$xalanc_lib" `
      "-DXMLSECURITYC_LIBRARY=$target/xmlsec/Build/$xmlsec_lib" `
      "-DXMLSECURITYC_INCLUDE_DIR=$target/xmlsec" `
      "-DXSD_INCLUDE_DIR=$target/xsd/libxsd" `
      "-DXSD_EXECUTABLE=$target/xsd/bin/xsd.exe" `
      "-DZLIB_ROOT=$target/zlib/$platform" `
      "-DSIGNCERT=$sign" `
      "-DCROSSSIGNCERT=$crosssign" `
      $cmakeext $libdigidocpp "&&" $nmake /nologo install
    Pop-Location
  }
}

if($doxygen) {
  & $heat dir x86/share/doc/libdigidocpp -nologo -cg Documentation -gg -scom -sreg -sfrag -srd -dr DocumentationFolder -var var.docLocation -out DocFilesFragment.wxs
}
& $heat dir x86/include -nologo -cg Headers -gg -scom -sreg -sfrag -srd -dr HeadersFolder -var var.headersLocation -out HeadersFragment.wxs
& $vcvars x86 "&&" $candle -nologo "-dICON=$libdigidocpp/cmake/modules/ID.ico" "-dMSI_VERSION=$msiversion" "-dPREFIX=$target" `
  "-dheadersLocation=x86/include" "-dlibdigidocpp=." $candleext $libdigidocpp\libdigidocpp.wxs HeadersFragment.wxs
& $light -nologo -out $msi_name -ext WixUIExtension `
  "-dWixUIBannerBmp=$libdigidocpp/cmake/modules/banner.bmp" `
  "-dWixUIDialogBmp=$libdigidocpp/cmake/modules/dlgbmp.bmp" `
  $lightext libdigidocpp.wixobj HeadersFragment.wixobj
 
if($sign) {
  signtool.exe sign /a /v /s MY /n "$sign" /fd SHA256 /du http://installer.id.ee `
    /tr http://sha256timestamp.ws.symantec.com/sha256/timestamp /td SHA256 "$msi_name"
}
