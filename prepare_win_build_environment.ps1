#powershell -ExecutionPolicy ByPass -File prepare_win_build_environment.ps1 [-openssl] [-xerces] [-xalan] [-xmlsec] [-xsd] [-zlib]
param(
	[string]$target = "C:\build",
	[string]$7zip = "C:\Program Files\7-Zip\7z.exe",
	[string]$cmake = "C:\Program Files (x86)\CMake\bin\cmake.exe",
	[string]$vstarget = "14",
	[string]$vsver = "$($vstarget).0",
	[string]$msbuildparams = "VisualStudioVersion=$vsver;PlatformToolset=v$($vstarget)0",
	[string]$msbuild = "C:\Program Files (x86)\MSBuild\$vsver\Bin\MSBuild.exe",
	[string]$VSINSTALLDIR = "C:\Program Files (x86)\Microsoft Visual Studio $vsver",
	[string]$devenv = "$VSINSTALLDIR\Common7\IDE\devenv.exe",
	[string]$vcvars = "$VSINSTALLDIR\VC\vcvarsall.bat",
	[string]$opensslver = "openssl-1.0.2q",
	[string]$xercesver = "xerces-c-3.2.2",
	[string]$xalanver = "xalan_c-1.11",
	[string]$xmlsecver = "xml-security-c-1.7.3",
	[string]$xsdver = "xsd-4.0.0-i686-windows",
	[string]$zlibver = "zlib-1.2.11",
	[string]$freetypever = "freetype-2.9.1",
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

$libdigidocpp = split-path -parent $MyInvocation.MyCommand.Definition
if(!(Test-Path -Path $target)){
	New-Item -ItemType directory -Path $target > $null
}
Push-Location -Path $target

[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
$client = new-object System.Net.WebClient

function openssl() {
	$client.DownloadFile("https://www.openssl.org/source/$opensslver.tar.gz", "$target\$opensslver.tar.gz")
	& $7zip x "$opensslver.tar.gz" > $null
	& $7zip x "$opensslver.tar" > $null
	Push-Location -Path $opensslver
	& $vcvars x86 "&&" perl Configure VC-WIN32 no-asm no-hw no-engines "&&" ms\do_ms "&&" nmake /nologo -f ms\ntdll.mak install INSTALLTOP=\OpenSSL-Win32 OPENSSLDIR=\OpenSSL-Win32\bin
	Pop-Location
	Remove-Item $opensslver -Force -Recurse

	& $7zip x "$opensslver.tar" > $null
	Push-Location -Path $opensslver
	& $vcvars x86_amd64 "&&" perl Configure VC-WIN64A no-asm no-hw no-engines "&&" ms\do_win64a "&&" nmake /nologo -f ms\ntdll.mak install INSTALLTOP=\OpenSSL-Win64 OPENSSLDIR=\OpenSSL-Win64\bin
	Pop-Location
	Remove-Item $opensslver -Force -Recurse
	Remove-Item "$opensslver.tar"
}

function xerces() {
	$client.DownloadFile("http://www.eu.apache.org/dist/xerces/c/3/sources/$xercesver.zip", "$target\$xercesver.zip")
	& $7zip x "$xercesver.zip" > $null
	Push-Location -Path $xercesver
	(Get-Content CMakeLists.txt) -replace 'add_subdirectory\(doc\)', '' -replace 'add_subdirectory\(tests\)', '' -replace 'add_subdirectory\(samples\)', '' | Set-Content CMakeLists.txt
	foreach($platform in @("x86", "x64")) {
		foreach($type in @("Debug", "RelWithDebInfo")) {
			$buildpath = $platform+$type
			New-Item -ItemType directory -Path $buildpath > $null
			Push-Location -Path $buildpath
			& $vcvars $platform "&&" $cmake "-DCMAKE_BUILD_TYPE=$type" "-DCMAKE_INSTALL_PREFIX=$target\xerces\$platform" "-GNMake Makefiles" .. "&&" nmake /nologo install # > $null
			Pop-Location
			Remove-Item $buildpath -Force -Recurse
		}
	}
	Pop-Location
	Remove-Item $xercesver -Force -Recurse
}

function xalan() {
	$client.DownloadFile("http://www.eu.apache.org/dist/xalan/xalan-c/sources/$xalanver-src.zip", "$target\$xalanver.zip")
	& $7zip x "$xalanver.zip" > $null
	Rename-Item "xalan-c-1.11" xalan
	Push-Location -Path xalan
	& git apply --ignore-space-change --ignore-whitespace --whitespace=nowarn $libdigidocpp\patches\xerces-char16_t.patch
	$xalanproj = "c\Projects\Win32\VC10\Xalan.sln"
	Get-ChildItem c\Projects\Win32\VC10 *.vcxproj -recurse | ForEach {
		(Get-Content $_.FullName) -replace '\<SmallerTypeCheck\>true\<\/SmallerTypeCheck\>', '' | Set-Content $_.FullName
	}
	$Env:XERCESCROOT="$target\xerces\x86"
	New-Item -ItemType directory -Path "c\Build\Win32\VC10\Release" -Force > $null
	New-Item -ItemType directory -Path "c\Build\Win32\VC10\Debug" -Force > $null
	Copy-Item "$Env:XERCESCROOT\bin\*.dll" "c\Build\Win32\VC10\Release"
	Copy-Item "$Env:XERCESCROOT\bin\*.dll" "c\Build\Win32\VC10\Debug"
	& $msbuild /nologo /verbosity:quiet "/p:$msbuildparams;Configuration=Release;Platform=Win32" "/t:AllInOne" $xalanproj
	& $msbuild /nologo /verbosity:quiet "/p:$msbuildparams;Configuration=Debug;Platform=Win32" "/t:AllInOne" $xalanproj
	$Env:XERCESCROOT="$target\xerces\x64"
	New-Item -ItemType directory -Path "c\Build\Win64\VC10\Release" -Force > $null
	New-Item -ItemType directory -Path "c\Build\Win64\VC10\Debug" -Force > $null
	Copy-Item "$Env:XERCESCROOT\bin\*.dll" "c\Build\Win64\VC10\Release"
	Copy-Item "$Env:XERCESCROOT\bin\*.dll" "c\Build\Win64\VC10\Debug"
	& $msbuild /nologo /verbosity:quiet "/p:$msbuildparams;Configuration=Release;Platform=X64" "/t:AllInOne" $xalanproj
	& $msbuild /nologo /verbosity:quiet "/p:$msbuildparams;Configuration=Debug;Platform=X64" "/t:AllInOne" $xalanproj
	Copy-Item "c\Build\Win32\VC10\Release\Nls\Include\*" "c\src\xalanc\PlatformSupport"
	Pop-Location
}

function xmlsec() {
	$client.DownloadFile("https://archive.apache.org/dist/santuario/c-library/$xmlsecver.tar.gz", "$target\$xmlsecver.tar.gz")
	& $7zip x "$xmlsecver.tar.gz" > $null
	& $7zip x "$xmlsecver.tar" > $null
	& $7zip x -y "$libdigidocpp\patches\$xmlsecver-VC12.zip" > $null
	$env:XALAN_PATH = "$target\xalan\c"
	Rename-Item $xmlsecver xmlsec
	$xsecproj = "xmlsec\Projects\VC12.0\xsec\xsec_lib\xsec_lib.vcxproj"
	$Env:XERCES_PATH="$target\xerces\x86"
	& $msbuild /nologo /verbosity:quiet "/p:$msbuildparams;Configuration=Release;Platform=Win32" $xsecproj
	& $msbuild /nologo /verbosity:quiet "/p:$msbuildparams;Configuration=Debug;Platform=Win32" $xsecproj
	$Env:XERCES_PATH="$target\xerces\x64"
	& $msbuild /nologo /verbosity:quiet "/p:$msbuildparams;Configuration=Release;Platform=X64" $xsecproj
	& $msbuild /nologo /verbosity:quiet "/p:$msbuildparams;Configuration=Debug;Platform=X64" $xsecproj
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
		& $vcvars $platform "&&" $cmake -DBUILD_SHARED_LIBS=YES -DCMAKE_BUILD_TYPE=Release "-DCMAKE_INSTALL_PREFIX=$target\zlib\$platform" "-GNMake Makefiles" . "&&" nmake /nologo install
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
		& $vcvars $platform "&&" $cmake -DCMAKE_BUILD_TYPE=Release "-DCMAKE_INSTALL_PREFIX=$target\freetype\$platform" "-GNMake Makefiles" .. "&&" nmake /nologo install
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
		del cmake/modules/FindFREETYPE.cmake
		del cmake/modules/FindOpenSSL.cmake
		del cmake/modules/FindZLIB.cmake
		(Get-Content CMakeLists.txt) -replace '\$\{PNG_LIBRARIES\}', '' | Set-Content CMakeLists.txt
		(Get-Content src/doc/PdfSignatureField.cpp) -replace 'adbe.pkcs7.detached', 'ETSI.CAdES.detached' | Set-Content src/doc/PdfSignatureField.cpp
		& $vcvars $platform "&&" $cmake "-GNMake Makefiles" -DCMAKE_BUILD_TYPE=Release -DPODOFO_BUILD_LIB_ONLY=YES `
			"-DCMAKE_INSTALL_PREFIX=$target\podofo\$platform" -DPODOFO_BUILD_STATIC=NO -DPODOFO_BUILD_SHARED=YES `
			"-DZLIB_INCLUDE_DIR=$target\zlib\$platform\include" "-DZLIB_LIBRARY_RELEASE=$target\zlib\$platform\lib\zlib.lib" `
			"-DFREETYPE_INCLUDE_DIR=$target\freetype\$platform\include\freetype2" "-DFREETYPE_LIBRARY=$target\freetype\$platform\lib\freetype.lib" . "&&" nmake /nologo install
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
