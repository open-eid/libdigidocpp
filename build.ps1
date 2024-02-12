#powershell -ExecutionPolicy ByPass -File build.ps1
param(
  [string]$libdigidocpp = $PSScriptRoot,
  [string]$vcpkg = "vcpkg\vcpkg.exe",
  [string]$vcpkg_dir = (split-path -parent $vcpkg),
  [string]$vcpkg_installed = $libdigidocpp,
  [string]$buildver = "0",
  [string]$msiversion = "3.18.0.$buildver",
  [string]$platform = "x64",
  [string]$msi_name = "libdigidocpp-$msiversion$env:VER_SUFFIX.$platform.msi",
  [string]$cmake = "cmake.exe",
  [string]$generator = "NMake Makefiles",
  [string]$vcvars = "vcvarsall",
  [string]$wix = "$env:WIX",
  [string]$heat = "$wix\bin\heat.exe",
  [string]$candle = "$wix\bin\candle.exe",
  [string]$light = "$wix\bin\light.exe",
  [string]$swig = $null,
  [string]$doxygen = $null,
  [switch]$boost = $false,
  [string]$xsd = "$libdigidocpp\xsd",
  [string]$sign = $null
)

$cmakeext = @()
$candleext = @()
$lightext = @()
$target = @("all")
if($swig) {
  $cmakeext += "-DSWIG_EXECUTABLE=$swig"
  $candleext += "-dswig=$swig"
}
if($doxygen) {
  $cmakeext += "-DDOXYGEN_EXECUTABLE=$doxygen"
  $candleext += "-ddocLocation=$platform/share/doc/libdigidocpp", "DocFilesFragment.wxs"
  $lightext += "DocFilesFragment.wixobj"
}
if($boost) {
  $cmakeext += "-DVCPKG_MANIFEST_FEATURES=tests"
  $target += "check"
}

foreach($type in @("Debug", "RelWithDebInfo")) {
  $buildpath = $platform+$type
  & $vcvars $platform "&&" $cmake --fresh -B $buildpath -S $libdigidocpp "-G$generator" `
    "-DCMAKE_BUILD_TYPE=$type" `
    "-DCMAKE_INSTALL_PREFIX=$platform" `
    "-DCMAKE_INSTALL_LIBDIR=bin" `
    "-DCMAKE_TOOLCHAIN_FILE=$vcpkg_dir/scripts/buildsystems/vcpkg.cmake" `
    "-DVCPKG_INSTALLED_DIR=$vcpkg_installed\vcpkg_installed_$platform" `
    "-DXSD_ROOT=$xsd" `
    "-DSIGNCERT=$sign" `
    $cmakeext "&&" $cmake --build $buildpath --target $target "&&" $cmake --install $buildpath
}

if($doxygen) {
  & $heat dir $platform/share/doc/libdigidocpp -nologo -cg Documentation -gg -scom -sreg -sfrag -srd -dr DocumentationFolder -var var.docLocation -out DocFilesFragment.wxs
}
& $heat dir $platform/include -nologo -cg Headers -gg -scom -sreg -sfrag -srd -dr HeadersFolder -var var.headersLocation -out HeadersFragment.wxs
& $candle -nologo -arch $platform "-dICON=$libdigidocpp/cmake/modules/ID.ico" "-dMSI_VERSION=$msiversion" `
  "-dvcpkg=$vcpkg_installed\vcpkg_installed_$platform\$platform-windows" "-dheadersLocation=$platform/include" `
  "-dlibdigidocpp=$platform" $candleext $libdigidocpp\libdigidocpp.wxs HeadersFragment.wxs
& $light -nologo -out $msi_name -ext WixUIExtension `
  "-dWixUIBannerBmp=$libdigidocpp/cmake/modules/banner.bmp" `
  "-dWixUIDialogBmp=$libdigidocpp/cmake/modules/dlgbmp.bmp" `
  $lightext libdigidocpp.wixobj HeadersFragment.wixobj

if($sign) {
  signtool.exe sign /a /v /s MY /n "$sign" /fd SHA256 /du http://installer.id.ee `
    /tr http://sha256timestamp.ws.symantec.com/sha256/timestamp /td SHA256 "$msi_name"
}
