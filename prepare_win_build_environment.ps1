#powershell -ExecutionPolicy ByPass -File prepare_win_build_environment.ps1 [-dependencies] [-xsd]
param(
	[string]$vcpkg = "vcpkg\vcpkg.exe",
	[string]$git = "git.exe",
	[switch]$xsd = $false,
	[switch]$wix = $false,
	[switch]$dependencies = $false
)

if($xsd) {
	$client = new-object System.Net.WebClient
	& mkdir xsd
	foreach($xsdver in @("xsd-4.2.0-x86_64-windows10", "libxsd-4.2.0-windows")) {
		$client.DownloadFile("https://www.codesynthesis.com/download/xsd/4.2/windows/windows10/x86_64/$xsdver.zip", "$PSScriptRoot\$xsdver.zip")
		& tar xf "$xsdver.zip"
		& xcopy /e /r /y $xsdver\*.* xsd
		& Remove-Item $xsdver -Force -Recurse -ErrorAction Ignore
	}
}

if($wix) {
	& dotnet tool install --global wix
	& wix extension add -g WixToolset.UI.wixext
}

if($dependencies) {
	if(!(Test-Path -Path $vcpkg)) {
		$vcpkg_dir = (split-path -parent $vcpkg)
		& $git clone --depth 1 https://github.com/microsoft/vcpkg $vcpkg_dir
		& $vcpkg_dir\bootstrap-vcpkg.bat
	}
	& $vcpkg install --clean-after-build --triplet x86-windows --x-feature=tests --x-install-root=vcpkg_installed_x86
	& $vcpkg install --clean-after-build --triplet x64-windows --x-feature=tests --x-install-root=vcpkg_installed_x64
}

