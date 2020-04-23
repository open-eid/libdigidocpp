#powershell -ExecutionPolicy ByPass -File prepare_win_build_environment.ps1 [-openssl] [-xerces] [-xalan] [-xmlsec] [-xsd] [-zlib]
param(
	[string]$target = "C:\build",
	[string]$7zip = "C:\Program Files\7-Zip\7z.exe",
	[string]$cmake = "cmake.exe",
	[string]$nmake = "nmake.exe",
	[string]$generator = "NMake Makefiles",
	[string]$toolset = "140",
	[string]$windowssdkversion = $(Get-Item "hklm:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SDKs\Windows\v10.0").GetValue("ProductVersion"),
	[string]$msbuildparams = "PlatformToolset=v$toolset;WindowsTargetPlatformVersion=$($windowssdkversion).0",
	[string]$opensslver = "openssl-1.1.1g",
	[string]$xercesver = "xerces-c-3.2.3",
	[string]$xalanver = "xalan_c-1.11",
	[string]$xmlsecver = "xml-security-c-2.0.2",
	[string]$xsdver = "xsd-4.0.0-i686-windows",
	[string]$zlibver = "zlib-1.2.11",
	[string]$freetypever = "freetype-2.10.1",
	[string]$podofover = "podofo-0.9.4",
	[switch]$openssl = $false,
	[switch]$xerces = $false,
	[switch]$xalan = $false,
	[switch]$xmlsec = $false,
	[switch]$xsd = $false,
	[switch]$zlib = $false,
	[switch]$freetype = $false,
	[switch]$podofo = $false
)

switch ($toolset) {
'140' { $vcvars = "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" }
'141' { $vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat" }
'142' { $vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" }
}

$libdigidocpp = split-path -parent $MyInvocation.MyCommand.Definition
if(!(Test-Path -Path $target)){
	New-Item -ItemType directory -Path $target > $null
}
Push-Location -Path $target

$client = new-object System.Net.WebClient

function openssl() {
	$client.DownloadFile("https://www.openssl.org/source/$opensslver.tar.gz", "$target\$opensslver.tar.gz")
	& $7zip x -y "$opensslver.tar.gz" > $null
	& $7zip x -y "$opensslver.tar" > $null
	Push-Location -Path $opensslver
	& $vcvars x86 "&&" perl Configure VC-WIN32 no-asm no-hw no-engine no-tests "&&" nmake /nologo install_sw INSTALLTOP=\OpenSSL-Win32 OPENSSLDIR=\OpenSSL-Win32\bin ENGINESDIR=\OpenSSL-Win32\lib\engines-1_1
	Pop-Location
	Remove-Item $opensslver -Force -Recurse

	& $7zip x -y "$opensslver.tar" > $null
	Push-Location -Path $opensslver
	& $vcvars x64 "&&" perl Configure VC-WIN64A no-asm no-hw no-engine no-tests "&&" nmake /nologo install_sw INSTALLTOP=\OpenSSL-Win64 OPENSSLDIR=\OpenSSL-Win64\bin ENGINESDIR=\OpenSSL-Win64\lib\engines-1_1
	Pop-Location
	Remove-Item $opensslver -Force -Recurse
	Remove-Item "$opensslver.tar"
}

function xerces() {
	$client.DownloadFile("https://archive.apache.org/dist/xerces/c/3/sources/$xercesver.zip", "$target\$xercesver.zip")
	& $7zip x "$xercesver.zip" > $null
	Push-Location -Path $xercesver
	(Get-Content CMakeLists.txt) -replace 'add_subdirectory\(doc\)', '' -replace 'add_subdirectory\(tests\)', '' -replace 'add_subdirectory\(samples\)', '' | Set-Content CMakeLists.txt
	foreach($platform in @("x86", "x64")) {
		foreach($type in @("Debug", "RelWithDebInfo")) {
			$buildpath = $platform+$type
			New-Item -ItemType directory -Path $buildpath > $null
			Push-Location -Path $buildpath
			& $vcvars $platform "&&" $cmake "-DCMAKE_BUILD_TYPE=$type" "-DCMAKE_INSTALL_PREFIX=$target\xerces\$platform" "-G$generator" .. "&&" $nmake /nologo install # > $null
			Pop-Location
			Remove-Item $buildpath -Force -Recurse
		}
	}
	Pop-Location
	Remove-Item $xercesver -Force -Recurse
}

function xalan() {
	$client.DownloadFile("https://archive.apache.org/dist/xalan/xalan-c/sources/$xalanver-src.zip", "$target\$xalanver.zip")
	& $7zip x "$xalanver.zip" > $null
	Rename-Item "xalan-c-1.11" xalan
	Push-Location -Path xalan
	& git apply --ignore-space-change --ignore-whitespace --whitespace=nowarn $libdigidocpp\patches\xerces-char16_t.patch
	& git apply --ignore-space-change --ignore-whitespace --whitespace=nowarn $libdigidocpp\patches\xalan-winproj.patch
	$xalanproj = "c\Projects\Win32\VC10\Xalan.sln"
	$Env:XERCESCROOT="$target\xerces\x86"
	New-Item -ItemType directory -Path "c\Build\Win32\VC10\Release" -Force > $null
	New-Item -ItemType directory -Path "c\Build\Win32\VC10\Debug" -Force > $null
	Copy-Item "$Env:XERCESCROOT\bin\*.dll" "c\Build\Win32\VC10\Release"
	Copy-Item "$Env:XERCESCROOT\bin\*.dll" "c\Build\Win32\VC10\Debug"
	& $vcvars x86 "&&" msbuild /nologo /verbosity:quiet "/p:$msbuildparams;Configuration=Release;Platform=Win32" "/t:AllInOne" $xalanproj
	& $vcvars x86 "&&" msbuild /nologo /verbosity:quiet "/p:$msbuildparams;Configuration=Debug;Platform=Win32" "/t:AllInOne" $xalanproj
	$Env:XERCESCROOT="$target\xerces\x64"
	New-Item -ItemType directory -Path "c\Build\Win64\VC10\Release" -Force > $null
	New-Item -ItemType directory -Path "c\Build\Win64\VC10\Debug" -Force > $null
	Copy-Item "$Env:XERCESCROOT\bin\*.dll" "c\Build\Win64\VC10\Release"
	Copy-Item "$Env:XERCESCROOT\bin\*.dll" "c\Build\Win64\VC10\Debug"
	& $vcvars x86 "&&" msbuild /nologo /verbosity:quiet "/p:$msbuildparams;Configuration=Release;Platform=X64" "/t:AllInOne" $xalanproj
	& $vcvars x86 "&&" msbuild /nologo /verbosity:quiet "/p:$msbuildparams;Configuration=Debug;Platform=X64" "/t:AllInOne" $xalanproj
	Copy-Item "c\Build\Win32\VC10\Release\Nls\Include\*" "c\src\xalanc\PlatformSupport"
	Pop-Location
}

function xmlsec() {
	$client.DownloadFile("https://archive.apache.org/dist/santuario/c-library/$xmlsecver.tar.gz", "$target\$xmlsecver.tar.gz")
	& $7zip x "$xmlsecver.tar.gz" > $null
	& $7zip x "$xmlsecver.tar" > $null
	Rename-Item $xmlsecver xmlsec
	Push-Location -Path xmlsec
	& git apply --ignore-space-change --ignore-whitespace --whitespace=nowarn $libdigidocpp\patches\xml-security-c-2.0.1-win.patch
	$xsecproj = "Projects\VC15.0\xsec\xsec_lib\xsec_lib.vcxproj"
	& $vcvars x86 "&&" msbuild /nologo /verbosity:quiet "/p:$msbuildparams;Configuration=Release;Platform=Win32;OPENSSLROOT=C:\OpenSSL-Win32;XERCESCROOT=$target\xerces\x86;XALANCROOT=$target\xalan\c" $xsecproj
	& $vcvars x86 "&&" msbuild /nologo /verbosity:quiet "/p:$msbuildparams;Configuration=Debug;Platform=Win32;OPENSSLROOT=C:\OpenSSL-Win32;XERCESCROOT=$target\xerces\x86;XALANCROOT=$target\xalan\c" $xsecproj
	& $vcvars x86 "&&" msbuild /nologo /verbosity:quiet "/p:$msbuildparams;Configuration=Release;Platform=X64;OPENSSLROOT=C:\OpenSSL-Win64;XERCESCROOT=$target\xerces\x64;XALANCROOT=$target\xalan\c" $xsecproj
	& $vcvars x86 "&&" msbuild /nologo /verbosity:quiet "/p:$msbuildparams;Configuration=Debug;Platform=X64;OPENSSLROOT=C:\OpenSSL-Win64;XERCESCROOT=$target\xerces\x64;XALANCROOT=$target\xalan\c" $xsecproj
	Pop-Location
}

function xsd() {
	$client.DownloadFile("http://www.codesynthesis.com/download/xsd/4.0/windows/i686/$xsdver.zip", "$target\$xsdver.zip")
	& $7zip x "$xsdver.zip" > $null
	Rename-Item $xsdver xsd
}

function zlib() {
	$client.DownloadFile("http://zlib.net/$zlibver.tar.gz", "$target\$zlibver.tar.gz")
	& $7zip x "$zlibver.tar.gz" > $null
	foreach($platform in @("x86", "x64")) {
		& $7zip x "$zlibver.tar" > $null
		Push-Location -Path $zlibver
		& $vcvars $platform "&&" $cmake -DBUILD_SHARED_LIBS=YES -DCMAKE_BUILD_TYPE=Release "-DCMAKE_INSTALL_PREFIX=$target\zlib\$platform" "-G$generator" . "&&" $nmake /nologo install
		Pop-Location
		Remove-Item $zlibver -Force -Recurse
	}
	Remove-Item "$zlibver.tar"
}

function freetype() {
	$client.DownloadFile("http://download.savannah.gnu.org/releases/freetype/$freetypever.tar.bz2", "$target\$freetypever.tar.gz")
	& $7zip x "$freetypever.tar.gz" > $null
	& $7zip x "$freetypever.tar" > $null
	Push-Location -Path $freetypever
	foreach($platform in @("x86", "x64")) {
		New-Item -ItemType directory -Path build > $null
		Push-Location -Path build
		& $vcvars $platform "&&" $cmake -DCMAKE_BUILD_TYPE=Release "-DCMAKE_INSTALL_PREFIX=$target\freetype\$platform" "-G$generator" .. "&&" $nmake /nologo install
		Pop-Location
		Remove-Item build -Force -Recurse
	}
	Pop-Location
	Remove-Item $freetypever -Force -Recurse
	Remove-Item "$freetypever.tar"
}

function podofo() {
	$client.DownloadFile("http://downloads.sourceforge.net/project/podofo/podofo/0.9.4/$podofover.tar.gz", "$target\$podofover.tar.gz")
	& $7zip x "$podofover.tar.gz" > $null
	foreach($platform in @("x86", "x64")) {
		& $7zip x "$podofover.tar" > $null
		Push-Location -Path $podofover
		Remove-Item cmake/modules/FindFREETYPE.cmake
		Remove-Item cmake/modules/FindOpenSSL.cmake
		Remove-Item cmake/modules/FindZLIB.cmake
		(Get-Content CMakeLists.txt) -replace '\$\{PNG_LIBRARIES\}', '' | Set-Content CMakeLists.txt
		(Get-Content src/doc/PdfSignatureField.cpp) -replace 'adbe.pkcs7.detached', 'ETSI.CAdES.detached' | Set-Content src/doc/PdfSignatureField.cpp
		& $vcvars $platform "&&" $cmake "-G$generator" -DCMAKE_BUILD_TYPE=Release -DPODOFO_BUILD_LIB_ONLY=YES `
			"-DCMAKE_INSTALL_PREFIX=$target\podofo\$platform" -DPODOFO_BUILD_STATIC=NO -DPODOFO_BUILD_SHARED=YES `
			"-DZLIB_INCLUDE_DIR=$target\zlib\$platform\include" "-DZLIB_LIBRARY_RELEASE=$target\zlib\$platform\lib\zlib.lib" `
			"-DFREETYPE_INCLUDE_DIR=$target\freetype\$platform\include\freetype2" "-DFREETYPE_LIBRARY=$target\freetype\$platform\lib\freetype.lib" . "&&" $nmake /nologo install
		Pop-Location
		Remove-Item $podofover -Force -Recurse
	}
	Remove-Item "$podofover.tar"
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
if($freetype) {
	freetype
}
if($podofo) {
	podofo
}
if(!$openssl -and !$xerces -and !$xalan -and !$xmlsec -and !$xsd -and !$zlib -and !$freetype -and !$podofo) {
	openssl
	xerces
	xalan
	xmlsec
	xsd
	zlib
}
Pop-Location
