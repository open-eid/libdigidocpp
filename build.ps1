#powershell -ExecutionPolicy ByPass -File build.ps1
param(
  [string]$libdigidocpp = $PSScriptRoot,
  [string]$platform = $env:PLATFORM,
  [string]$build_number = $(if ($null -eq $env:BUILD_NUMBER) {"0"} else {$env:BUILD_NUMBER}),
  [string]$msiversion = "4.4.0.$build_number",
  [string]$msi_name = "libdigidocpp-$msiversion$env:VER_SUFFIX.$platform.msi",
  [string]$git = "git.exe",
  [string]$vcpkg = "vcpkg\vcpkg.exe",
  [string]$vcpkg_dir = (split-path -parent $vcpkg),
  [string]$vcpkg_installed = $libdigidocpp,
  [string]$vcpkg_installed_platform = "$vcpkg_installed\vcpkg_installed_$platform",
  [string]$vcpkg_triplet = "$platform-windows",
  [string]$cmake = "cmake.exe",
  [string]$generator = "NMake Makefiles",
  [string]$swig = $null,
  [string]$doxygen = $null,
  [switch]$boost = $false,
  [string]$sign = $null
)

Try {
  & wix > $null
}
Catch {
  & dotnet tool install -g --version 6.0.2 wix
  & wix extension add -g WixToolset.UI.wixext/6.0.2
}

if(!(Test-Path -Path $vcpkg)) {
  & $git clone https://github.com/microsoft/vcpkg $vcpkg_dir
  & $vcpkg_dir\bootstrap-vcpkg.bat
}

$cmakeext = @()
$wixext = @()
$target = @("all")
if($swig) {
  $cmakeext += "-DSWIG_EXECUTABLE=$swig"
  $wixext += "-d", "swig=$swig"
}
if($doxygen) {
  $cmakeext += "-DDOXYGEN_EXECUTABLE=$doxygen"
}
if($platform -eq "arm64" -and $env:VSCMD_ARG_HOST_ARCH -ne "arm64") {
  $cmakeext += "-DCMAKE_DISABLE_FIND_PACKAGE_Python3=yes"
  $wixext += "-d", "disablePython=1"
  $boost = $false
}
if($boost) {
  $cmakeext += "-DVCPKG_MANIFEST_FEATURES=tests"
  $target += "check"
}

foreach($type in @("Debug", "RelWithDebInfo")) {
  $buildpath = $platform+$type
  & $cmake --fresh -B $buildpath -S $libdigidocpp "-G$generator" $cmakeext `
    "-DCMAKE_BUILD_TYPE=$type" `
    "-DCMAKE_INSTALL_PREFIX=$platform" `
    "-DCMAKE_INSTALL_BINDIR=." `
    "-DCMAKE_INSTALL_LIBDIR=." `
    "-DCMAKE_TOOLCHAIN_FILE=$vcpkg_dir/scripts/buildsystems/vcpkg.cmake" `
    "-DVCPKG_INSTALLED_DIR=$vcpkg_installed_platform" `
    "-DVCPKG_TARGET_TRIPLET=$vcpkg_triplet" `
    "-DSIGNCERT=$sign"
  & $cmake --build $buildpath --target $target
  & $cmake --install $buildpath
}

if($sign) {
  & signtool.exe sign /a /v /s MY /n "$sign" /fd SHA256 /du http://installer.id.ee `
    /tr http://timestamp.digicert.com /td SHA256 `
    $vcpkg_installed_platform/$vcpkg_triplet/bin/*.dll `
    $vcpkg_installed_platform/$vcpkg_triplet/debug/bin/*.dll
}

$docLocation = "$(Get-Location)/$platform/share/doc/libdigidocpp"
if (Test-Path -Path $docLocation -PathType Container) {
  $wixext += "-d", "docLocation=$docLocation"
}

& wix build -nologo -arch $platform -out $msi_name $wixext `
  -ext WixToolset.UI.wixext `
  -bv "WixUIBannerBmp=$libdigidocpp/banner.bmp" `
  -bv "WixUIDialogBmp=$libdigidocpp/dlgbmp.bmp" `
  -d "ICON=$libdigidocpp/ID.ico" `
  -d "vcpkg=$vcpkg_installed_platform/$vcpkg_triplet" `
  -d "libdigidocpp=$(Get-Location)/$platform" `
  $libdigidocpp\libdigidocpp.wxs

if($sign) {
  & signtool.exe sign /a /v /s MY /n "$sign" /fd SHA256 /du http://installer.id.ee `
    /tr http://timestamp.digicert.com /td SHA256 "$msi_name"
}
