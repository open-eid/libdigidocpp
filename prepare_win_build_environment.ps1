#powershell -ExecutionPolicy ByPass -File prepare_win_build_environment.ps1 [-dependencies] [-xsd]
param(
	[string]$vcpkg = "vcpkg\vcpkg.exe",
	[string]$git = "git.exe",
	[string]$7zip = "C:\Program Files\7-Zip\7z.exe",
	[string]$toolset = "142",
	[string]$xsdver = "xsd-4.0.0-i686-windows",
	[switch]$xsd = $false,
	[switch]$dependencies = $false
)

if(!(Test-Path -Path $vcpkg)) {
	$vcpkg_dir = (split-path -parent $vcpkg)
	& $git clone --depth 1 https://github.com/microsoft/vcpkg $vcpkg_dir
	& $vcpkg_dir\bootstrap-vcpkg.bat
}

function xsd() {
	$client = new-object System.Net.WebClient
	$client.DownloadFile("http://www.codesynthesis.com/download/xsd/4.0/windows/i686/$xsdver.zip", "$PSScriptRoot\$xsdver.zip")
	& $7zip x "$xsdver.zip" > $null
	Rename-Item $xsdver xsd
}

if($xsd) {
	xsd
}

if($dependencies) {
	& $vcpkg install --clean-after-build --triplet x86-windows-v$toolset --x-feature=tests --x-install-root=vcpkg_installed_x86
	& $vcpkg install --clean-after-build --triplet x64-windows-v$toolset --x-feature=tests --x-install-root=vcpkg_installed_x64
}

if(!$xsd -and !$dependencies) {
	xsd
}

