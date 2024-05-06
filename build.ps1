#powershell -ExecutionPolicy ByPass -File build.ps1
param(
  [string]$libdigidocpp = $PSScriptRoot,
  [string]$vcpkg = "vcpkg\vcpkg.exe",
  [string]$vcpkg_dir = (split-path -parent $vcpkg),
  [string]$vcpkg_installed = $libdigidocpp,
  [string]$build_number = $(if ($null -eq $env:BUILD_NUMBER) {"0"} else {$env:BUILD_NUMBER}),
  [string]$msiversion = "3.18.0.$build_number",
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

$cmakeext = @()
$wixext = @()
$target = @("all")
if($swig) {
  $cmakeext += "-DSWIG_EXECUTABLE=$swig"
  $wixext += "-d", "swig=$swig"
}
if($doxygen) {
  $cmakeext += "-DDOXYGEN_EXECUTABLE=$doxygen"
  $wixext += "-d", "docLocation=$(Get-Location)/$platform/share/doc/libdigidocpp"
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

& $vcvars $platform "&&" $wix build -nologo -arch $platform -out $msi_name $wixext `
  -ext WixToolset.UI.wixext `
  -bv "WixUIBannerBmp=$libdigidocpp/cmake/modules/banner.bmp" `
  -bv "WixUIDialogBmp=$libdigidocpp/cmake/modules/dlgbmp.bmp" `
  -d "ICON=$libdigidocpp/cmake/modules/ID.ico" `
  -d "MSI_VERSION=$msiversion" `
  -d "vcpkg=$vcpkg_installed/vcpkg_installed_$platform/$platform-windows" `
  -d "libdigidocpp=$(Get-Location)/$platform" `
  $libdigidocpp\libdigidocpp.wxs

if($sign) {
  signtool.exe sign /a /v /s MY /n "$sign" /fd SHA256 /du http://installer.id.ee `
    /tr http://sha256timestamp.ws.symantec.com/sha256/timestamp /td SHA256 "$msi_name"
}
