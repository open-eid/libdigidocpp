#powershell -ExecutionPolicy ByPass -File build.ps1
param(
  [string]$libdigidocpp = $PSScriptRoot,
  [string]$platform = $env:PLATFORM,
  [string]$build_number = $(if ($null -eq $env:BUILD_NUMBER) {"0"} else {$env:BUILD_NUMBER}),
  [string]$msiversion = (Select-String -Path "$libdigidocpp/CMakeLists.txt" -Pattern 'project\(\w+ VERSION (\S+)').Matches[0].Groups[1].Value + ".$build_number",
  [string]$msi_name = "libdigidocpp-$msiversion$env:VER_SUFFIX.$platform.msi",
  [string]$git = "git.exe",
  [string]$vcpkg = $env:VCPKG_ROOT,
  [string]$vcpkg_installed = $null,
  [string]$vcpkg_installed_platform = $(if($vcpkg_installed) { "$vcpkg_installed\vcpkg_installed_$platform" } else { "$libdigidocpp\build\windows-$platform\vcpkg_installed" }),
  [string]$vcpkg_triplet = "$platform-windows",
  [string]$installdir = "$libdigidocpp\build\windows-$platform\install",
  [string]$cmake = "cmake.exe",
  [string]$swig = $null,
  [string]$doxygen = $null,
  [switch]$boost = $false,
  [string]$sign = $null,
  [string]$python = $null
)

Try {
  & wix > $null
}
Catch {
  & dotnet tool install -g --version 6.0.2 wix
  & wix extension add -g WixToolset.UI.wixext/6.0.2
}

if(!(Test-Path -Path $vcpkg)) {
  $vcpkg = "$libdigidocpp\vcpkg"
  & $git clone https://github.com/microsoft/vcpkg $vcpkg
  & $vcpkg\bootstrap-vcpkg.bat
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
  $boost = $false
}
if($boost) {
  $cmakeext += "-DVCPKG_MANIFEST_FEATURES=tests"
  $target += "check"
}
if($python) {
  $cmakeext += "-DPython3_ROOT_DIR=$python/$platform"
  $wixext += "-d", "python=1"
}
if($vcpkg_installed) {
  $cmakeext += "-DVCPKG_INSTALLED_DIR=$vcpkg_installed_platform"
}
$env:PLATFORM = $platform
$env:VCPKG_ROOT = $vcpkg

Push-Location $libdigidocpp
& $cmake --fresh --preset windows "-GNinja Multi-Config" $cmakeext "-DCMAKE_INSTALL_PREFIX=$installdir" "-DSIGNCERT=$sign"
foreach($type in @("Debug", "RelWithDebInfo")) {
  & $cmake --build --preset windows --config $type --target $target
  & $cmake --build --preset windows --config $type --target install
}
Pop-Location

if($sign) {
  & signtool.exe sign /a /v /s MY /n "$sign" /fd SHA256 /du http://installer.id.ee `
    /tr http://timestamp.digicert.com /td SHA256 `
    $vcpkg_installed_platform/$vcpkg_triplet/bin/*.dll `
    $vcpkg_installed_platform/$vcpkg_triplet/debug/bin/*.dll
}

$docLocation = "$installdir/share/doc/libdigidocpp"
if (Test-Path -Path $docLocation -PathType Container) {
  $wixext += "-d", "docLocation=$docLocation"
}

& wix build -nologo -arch $platform -out $msi_name $wixext `
  -ext WixToolset.UI.wixext `
  -bv "WixUIBannerBmp=$libdigidocpp/banner.bmp" `
  -bv "WixUIDialogBmp=$libdigidocpp/dlgbmp.bmp" `
  -d "ICON=$libdigidocpp/ID.ico" `
  -d "vcpkg=$vcpkg_installed_platform/$vcpkg_triplet" `
  -d "libdigidocpp=$installdir" `
  $libdigidocpp\libdigidocpp.wxs

if($sign) {
  & signtool.exe sign /a /v /s MY /n "$sign" /fd SHA256 /du http://installer.id.ee `
    /tr http://timestamp.digicert.com /td SHA256 "$msi_name"
}
