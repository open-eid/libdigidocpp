#powershell -ExecutionPolicy ByPass -File prepare_win_build_environment.ps1 [-openssl] [-xerces] [-xalan] [-xmlsec] [-xsd] [-zlib]
param(
	[string]$vcpkg = "vcpkg\vcpkg.exe",
	[string]$git = "git.exe",
	[string]$7zip = "C:\Program Files\7-Zip\7z.exe",
	[string]$toolset = "141",
	[string]$xsdver = "xsd-4.0.0-i686-windows",
	[switch]$openssl = $false,
	[switch]$xerces = $false,
	[switch]$xalan = $false,
	[switch]$xmlsec = $false,
	[switch]$zlib = $false,
	[switch]$xsd = $false,
	[switch]$freetype = $false,
	[switch]$podofo = $false
)

$env:VCPKG_OVERLAY_PORTS = "$PSScriptRoot\patches\vcpkg-ports"
$env:VCPKG_OVERLAY_TRIPLETS = "$PSScriptRoot\patches\vcpkg-triplets"

if(!(Test-Path -Path $vcpkg)) {
	$vcpkg_dir = (split-path -parent $vcpkg)
	& $git clone --depth 1 https://github.com/microsoft/vcpkg $vcpkg_dir
	& $vcpkg_dir\bootstrap-vcpkg.bat
}

function vcpkg_install($package) {
	& $vcpkg install "$($package):x86-windows-v$toolset" "$($package):x64-windows-v$toolset"
}

function xsd() {
	$client = new-object System.Net.WebClient
	$client.DownloadFile("http://www.codesynthesis.com/download/xsd/4.0/windows/i686/$xsdver.zip", "$PSScriptRoot\$xsdver.zip")
	& $7zip x "$xsdver.zip" > $null
	Rename-Item $xsdver xsd
}

if($openssl) {
	vcpkg_install("openssl")
}
if($xerces) {
	vcpkg_install("xerces-c")
}
if($xalan) {
	vcpkg_install("xalan-c")
}
if($xmlsec) {
	vcpkg_install("xml-security-c")
}
if($xsd) {
	xsd
}
if($zlib) {
	vcpkg_install("zlib")
}
if($freetype) {
	vcpkg_install("freetype")
}
if($podofo) {
	vcpkg_install("podofo")
}
if(!$openssl -and !$xerces -and !$xalan -and !$xmlsec -and !$xsd -and !$zlib -and !$freetype -and !$podofo) {
	vcpkg_install("openssl")
	vcpkg_install("xerces-c")
	vcpkg_install("xalan-c")
	vcpkg_install("xml-security-c")
	vcpkg_install("zlib")
	xsd
}
