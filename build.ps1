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
  [string]$wix = "wix.exe",
  [string]$swig = $null,
  [string]$doxygen = $null,
  [switch]$boost = $false,
  [string]$xsd = "$libdigidocpp\xsd",
  [string]$sign = $null
)

# Hack to fetch heat.exe tool
& dotnet new console -o wix-heat --force
& dotnet add wix-heat package WixToolset.Heat
$heat = Get-ChildItem "$env:USERPROFILE\.nuget\packages\WixToolset.Heat" -Include heat.exe -Recurse

$cmakeext = @()
$wixext = @()
$target = @("all")
if($swig) {
  $cmakeext += "-DSWIG_EXECUTABLE=$swig"
  $wixext += "-d", "swig=$swig"
}
if($doxygen) {
  $cmakeext += "-DDOXYGEN_EXECUTABLE=$doxygen"
  $wixext += "-d", "docLocation=$platform/share/doc/libdigidocpp", "DocFilesFragment.wxs"
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
  & $heat[0] dir $platform/share/doc/libdigidocpp -nologo -cg Documentation -gg -scom -sreg -sfrag -srd -dr DocumentationFolder -var var.docLocation -out DocFilesFragment.wxs
}

& $heat[0] dir $platform/include -nologo -cg Headers -gg -scom -sreg -sfrag -srd -dr HeadersFolder -var var.headersLocation -out HeadersFragment.wxs
& $wix build -nologo -arch $platform -out $msi_name $wixext `
  -ext WixToolset.UI.wixext `
  -bv "WixUIBannerBmp=$libdigidocpp/cmake/modules/banner.bmp" `
  -bv "WixUIDialogBmp=$libdigidocpp/cmake/modules/dlgbmp.bmp" `
  -d "ICON=$libdigidocpp/cmake/modules/ID.ico" `
  -d "MSI_VERSION=$msiversion" `
  -d "vcpkg=$vcpkg_installed/vcpkg_installed_$platform/$platform-windows" `
  -d "libdigidocpp=$platform" `
  -d "headersLocation=$platform/include" `
  HeadersFragment.wxs `
  $libdigidocpp\libdigidocpp.wxs

if($sign) {
  signtool.exe sign /a /v /s MY /n "$sign" /fd SHA256 /du http://installer.id.ee `
    /tr http://sha256timestamp.ws.symantec.com/sha256/timestamp /td SHA256 "$msi_name"
}
