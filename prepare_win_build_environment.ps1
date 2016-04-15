#powershell -ExecutionPolicy ByPass -File prepare_win_build_environment.ps1 [-openssl] [-xerces] [-xalan] [-xmlsec] [-xsd] [-zlib]
param(
	[string]$target = "C:\build",
	[string]$msbuild = "C:\Program Files (x86)\MSBuild\12.0\Bin\MSBuild.exe",
	[string]$7zip = "C:\Program Files\7-Zip\7z.exe",
	[string]$cmake = "C:\Program Files (x86)\CMake\bin\cmake.exe",
	[string]$devenv = "C:\Program Files (x86)\Microsoft Visual Studio 12.0\Common7\IDE\devenv.exe",
	[string]$vcvars = "C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\vcvarsall.bat", #$env:VCINSTALLDIR
	[string]$opensslver = "openssl-1.0.2h",
	[string]$xercesver = "xerces-c-3.1.4",
	[string]$xalanver = "xalan_c-1.11",
	[string]$xmlsecver = "xml-security-c-1.7.3",
	[string]$xsdver = "xsd-4.0.0-i686-windows",
	[string]$zlibver = "zlib-1.2.8",
	[switch]$openssl = $false,
	[switch]$xerces = $false,
	[switch]$xalan = $false,
	[switch]$xmlsec = $false,
	[switch]$xsd = $false,
	[switch]$zlib = $false
)

$libdigidocpp = split-path -parent $MyInvocation.MyCommand.Definition
if(!(Test-Path -Path $target)){
	New-Item -ItemType directory -Path $target
}
Push-Location -Path $target

[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
$shell = new-object -com shell.application
$client = new-object System.Net.WebClient

function openssl() {
	$client.DownloadFile("https://www.openssl.org/source/$opensslver.tar.gz", "$target\$opensslver.tar.gz")
	& $7zip x "$opensslver.tar.gz" > $null
	& $7zip x "$opensslver.tar" > $null
	Push-Location -Path $opensslver
	& $vcvars x86 "&&" perl Configure VC-WIN32 no-asm "&&" ms\do_ms "&&" nmake -f ms\ntdll.mak install INSTALLTOP=\OpenSSL-Win32 OPENSSLDIR=\OpenSSL-Win32\bin
	Pop-Location
	Remove-Item $opensslver -Force -Recurse

	& $7zip x "$opensslver.tar" > $null
	Push-Location -Path $opensslver
	& $vcvars x86_amd64 "&&" perl Configure VC-WIN64A no-asm "&&" ms\do_win64a "&&" nmake -f ms\ntdll.mak install INSTALLTOP=\OpenSSL-Win64 OPENSSLDIR=\OpenSSL-Win64\bin
	Pop-Location
	Remove-Item $opensslver -Force -Recurse
	Remove-Item "$opensslver.tar"
}

function xerces() {
	$client.DownloadFile("http://mirrors.advancedhosters.com/apache//xerces/c/3/sources/$xercesver.zip", "$target\$xercesver.zip")
	foreach($item in $shell.NameSpace("$target\$xercesver.zip").items()) {
		$shell.Namespace($target).CopyHere($item,0x14)
	}

	Rename-Item $xercesver xerces
	$xercesproj = "xerces\projects\Win32\VC12\xerces-all\xerces-all.sln"
	& $msbuild /nologo /verbosity:quiet "/p:Configuration=Release;Platform=Win32" $xercesproj
	& $msbuild /nologo /verbosity:quiet "/p:Configuration=Release;Platform=X64" $xercesproj
	& $msbuild /nologo /verbosity:quiet "/p:Configuration=Debug;Platform=Win32" $xercesproj
	& $msbuild /nologo /verbosity:quiet "/p:Configuration=Debug;Platform=X64" $xercesproj
}

function xalan() {
	$client.DownloadFile("http://www-eu.apache.org/dist/xalan/xalan-c/sources/$xalanver-src.zip", "$target\$xalanver.zip")
	foreach($item in $shell.NameSpace("$target\$xalanver.zip").items()) {
		$shell.Namespace($target).CopyHere($item,0x14)
	}
	Rename-Item "xalan-c-1.11" xalan
	$xalanproj = "xalan\c\Projects\Win32\VC10\Xalan.sln"
	& $devenv /upgrade "xalan\c\Projects\Win32\VC10\Xalan.sln"
	$Env:XERCESCROOT="$target\xerces"
	Copy-Item "$Env:XERCESCROOT\Build\Win32\VC12" "$Env:XERCESCROOT\Build\Win32\VC10" -Recurse -Force
	Copy-Item "$Env:XERCESCROOT\Build\Win64\VC12" "$Env:XERCESCROOT\Build\Win64\VC10" -Recurse -Force
	New-Item -ItemType directory -Path "xalan\c\Build\Win32\VC10\Release" -Force
	New-Item -ItemType directory -Path "xalan\c\Build\Win64\VC10\Release" -Force
	New-Item -ItemType directory -Path "xalan\c\Build\Win32\VC10\Debug" -Force
	New-Item -ItemType directory -Path "xalan\c\Build\Win64\VC10\Debug" -Force
	Copy-Item "$Env:XERCESCROOT\Build\Win32\VC12\Release\*.dll" "xalan\c\Build\Win32\VC10\Release"
	Copy-Item "$Env:XERCESCROOT\Build\Win64\VC12\Release\*.dll" "xalan\c\Build\Win64\VC10\Release"
	Copy-Item "$Env:XERCESCROOT\Build\Win32\VC12\Debug\*.dll" "xalan\c\Build\Win32\VC10\Debug"
	Copy-Item "$Env:XERCESCROOT\Build\Win64\VC12\Debug\*.dll" "xalan\c\Build\Win64\VC10\Debug"
	& $msbuild /nologo /verbosity:quiet "/p:PlatformToolset=v120;Configuration=Release;Platform=Win32" "/t:AllInOne" $xalanproj
	& $msbuild /nologo /verbosity:quiet "/p:PlatformToolset=v120;Configuration=Release;Platform=X64" "/t:AllInOne" $xalanproj
	& $msbuild /nologo /verbosity:quiet "/p:PlatformToolset=v120;Configuration=Debug;Platform=Win32" "/t:AllInOne" $xalanproj
	& $msbuild /nologo /verbosity:quiet "/p:PlatformToolset=v120;Configuration=Debug;Platform=X64" "/t:AllInOne" $xalanproj
	Copy-Item "xalan\c\Build\Win32\VC10\Release\Nls\Include\*" "xalan\c\src\xalanc\PlatformSupport"
}

function xmlsec() {
	$client.DownloadFile("http://mirrors.advancedhosters.com/apache//santuario/c-library/$xmlsecver.tar.gz", "$target\$xmlsecver.tar.gz")
	& $7zip x "$xmlsecver.tar.gz" > $null
	& $7zip x "$xmlsecver.tar" > $null
	foreach($item in $shell.NameSpace("$libdigidocpp\$xmlsecver-VC12.zip").items()) {
		$shell.Namespace($target).CopyHere($item,0x14)
	}

	$env:XERCES_PATH = "$target\xerces"
	$env:XALAN_PATH = "$target\xalan\c"
	Rename-Item $xmlsecver xmlsec
	$xsecproj = "xmlsec\Projects\VC12.0\xsec\xsec_lib\xsec_lib.vcxproj"
	& $msbuild /nologo /verbosity:quiet "/p:Configuration=Release;Platform=Win32" $xsecproj
	& $msbuild /nologo /verbosity:quiet "/p:Configuration=Release;Platform=X64" $xsecproj
	& $msbuild /nologo /verbosity:quiet "/p:Configuration=Debug;Platform=Win32" $xsecproj
	& $msbuild /nologo /verbosity:quiet "/p:Configuration=Debug;Platform=X64" $xsecproj
}

function xsd() {
	$client.DownloadFile("http://www.codesynthesis.com/download/xsd/4.0/windows/i686/$xsdver.zip", "$target\$xsdver.zip")
	foreach($item in $shell.NameSpace("$target\$xsdver.zip").items()) {
		$shell.Namespace($target).CopyHere($item,0x14)
	}
	Rename-Item $xsdver xsd
}

function zlib() {
	$client.DownloadFile("http://zlib.net/$zlibver.tar.gz", "$target\$zlibver.tar.gz")
	& $7zip x "$zlibver.tar.gz" > $null
	& $7zip x "$zlibver.tar" > $null
	Push-Location -Path $zlibver
	& $vcvars x86 "&&" $cmake -DBUILD_SHARED_LIBS=YES -DCMAKE_BUILD_TYPE=Release "-DCMAKE_INSTALL_PREFIX=$target\zlib\x86" "-GNMake Makefiles" . "&&" nmake install
	Pop-Location
	Remove-Item $zlibver -Force -Recurse

	& $7zip x "$zlibver.tar" > $null
	Push-Location -Path $zlibver
	& $vcvars x86_amd64 "&&" $cmake -DBUILD_SHARED_LIBS=YES -DCMAKE_BUILD_TYPE=Release "-DCMAKE_INSTALL_PREFIX=$target\zlib\x64" "-GNMake Makefiles" . "&&" nmake install
	Pop-Location
	Remove-Item $zlibver -Force -Recurse
	Remove-Item "$zlibver.tar"
}

if($openssl) {
	openssl
}
if($xerces) {
	xerces
}
if($xalan) {
	xalan
}
if($xmlsec) {
	xmlsec
}
if($xsd) {
	xsd
}
if($zlib) {
	zlib
}
if(!$openssl -and !$xerces -and !$xalan -and !$xmlsec -and !$xsd -and !$zlib) {
	openssl
	xerces
	xalan
	xmlsec
	xsd
	zlib
}
Pop-Location
