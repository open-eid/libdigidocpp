#powershell -ExecutionPolicy ByPass -File prepare_win_build_environment.ps1 [-dependencies] [-xsd]
param(
	[string]$vcpkg = "vcpkg\vcpkg.exe",
	[string]$git = "git.exe",
	[switch]$wix = $false,
	[switch]$dependencies = $false
)

if($wix) {
	& dotnet tool install --global wix
	& wix extension add -g WixToolset.UI.wixext/4.0.4
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

