#powershell -ExecutionPolicy ByPass -File build.ps1
param(
  [string]$libdigidocpp = $PSScriptRoot,
  [string]$vcpkg = "vcpkg\vcpkg.exe",
  [string]$vcpkg_dir = (split-path -parent $vcpkg),
  [string]$vcpkg_installed = $libdigidocpp,
  [string]$buildver = "0",
  [string]$msiversion = "3.18.0.$buildver",
  [string]$msi_name = "libdigidocpp-$msiversion$env:VER_SUFFIX.msi",
  [string]$cmake = "cmake.exe",
  [string]$generator = "NMake Makefiles",
  [string]$toolset = "142",
  [string]$vcvars = $null,
  [string]$vcver = "",
  [string]$heat = "$env:WIX\bin\heat.exe",
  [string]$candle = "$env:WIX\bin\candle.exe",
  [string]$light = "$env:WIX\bin\light.exe",
  [string]$swig = $null,
  [string]$doxygen = $null,
  [switch]$boost = $false,
  [string]$xsd = "$libdigidocpp\xsd",
  [string]$sign = $null,
  [string]$crosssign = $null,
  [switch]$source = $false
)

if (!$vcvars) {
  switch ($toolset) {
  '142' { $vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" }
  '143' { $vcvars = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" }
  }
}
if ($vcver) {
  $vcver = "-vcvars_ver=$vcver"
}

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
if($boost) {
  $cmakeext += "-DVCPKG_MANIFEST_FEATURES=tests"
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
    Remove-Item $buildpath -Force -Recurse -ErrorAction Ignore
    & $vcvars $platform $vcver "&&" $cmake -B $buildpath -S $libdigidocpp "-G$generator" `
      "-DCMAKE_BUILD_TYPE=$type" `
      "-DCMAKE_INSTALL_PREFIX=$platform" `
      "-DCMAKE_INSTALL_LIBDIR=bin" `
      "-DCMAKE_TOOLCHAIN_FILE=$vcpkg_dir/scripts/buildsystems/vcpkg.cmake" `
      "-DVCPKG_TARGET_TRIPLET=$platform-windows-v$toolset" `
      "-DVCPKG_INSTALLED_DIR=$vcpkg_installed\vcpkg_installed_$platform" `
      "-DXSD_ROOT=$xsd" `
      "-DSIGNCERT=$sign" `
      "-DCROSSSIGNCERT=$crosssign" `
      $cmakeext "&&" $cmake --build $buildpath --target check "&&" $cmake --build $buildpath --target install
  }
}

if($doxygen) {
  & $heat dir x86/share/doc/libdigidocpp -nologo -cg Documentation -gg -scom -sreg -sfrag -srd -dr DocumentationFolder -var var.docLocation -out DocFilesFragment.wxs
}
& $heat dir x86/include -nologo -cg Headers -gg -scom -sreg -sfrag -srd -dr HeadersFolder -var var.headersLocation -out HeadersFragment.wxs
& $vcvars x86 "&&" $candle -nologo "-dICON=$libdigidocpp/cmake/modules/ID.ico" "-dMSI_VERSION=$msiversion" `
  "-dvcpkg_x86=$vcpkg_installed\vcpkg_installed_x86\x86-windows-v$toolset" "-dvcpkg_x64=$vcpkg_installed\vcpkg_installed_x64\x64-windows-v$toolset" `
  "-dheadersLocation=x86/include" "-dlibdigidocpp=." $candleext $libdigidocpp\libdigidocpp.wxs HeadersFragment.wxs
& $light -nologo -out $msi_name -ext WixUIExtension `
  "-dWixUIBannerBmp=$libdigidocpp/cmake/modules/banner.bmp" `
  "-dWixUIDialogBmp=$libdigidocpp/cmake/modules/dlgbmp.bmp" `
  $lightext libdigidocpp.wixobj HeadersFragment.wixobj

if($sign) {
  signtool.exe sign /a /v /s MY /n "$sign" /fd SHA256 /du http://installer.id.ee `
    /tr http://sha256timestamp.ws.symantec.com/sha256/timestamp /td SHA256 "$msi_name"
}
