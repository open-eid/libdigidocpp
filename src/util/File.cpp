/*
 * libdigidocpp
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "File.h"

#include "log.h"

#include <algorithm>
#include <ctime>
#include <filesystem>
#include <locale>
#include <sstream>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#include <Windows.h>
#include <ShlObj_core.h>
#include <direct.h>
#include <sys/utime.h>
#else
#include <dirent.h>
#include <sys/param.h>
#include <pwd.h>
#include <unistd.h>
#include <utime.h>
#endif
#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#endif

using namespace digidoc;
using namespace digidoc::util;
using namespace std;
namespace fs = filesystem;

#ifdef _WIN32
#define f_stat _wstat64
#define f_utime _wutime64
using f_statbuf = struct _stat64;
using f_utimbuf = struct __utimbuf64;
#else
#define f_stat stat
#define f_utime utime
using f_statbuf = struct stat;
using f_utimbuf = struct utimbuf;
#endif

stack<string> File::tempFiles;

string File::confPath()
{
#if defined(__APPLE__)
    return frameworkResourcesPath("ee.ria.digidocpp");
#elif defined(_WIN32) && defined(_DEBUG)
    return dllPath("digidocppd.dll");
#elif defined(_WIN32)
    return dllPath("digidocpp.dll");
#else
    return path(env("SNAP"), DIGIDOCPP_CONFIG_DIR "/");
#endif
}

#ifndef _WIN32
string File::env(string_view varname)
{
    if(char *var = getenv(varname.data()))
        return decodeName(var);
    return {};
}
#endif

/**
 * Encodes path to compatible std lib
 * @param fileName path
 * @return encoded path
 */
File::f_string File::encodeName(string_view fileName)
{
    if(fileName.empty())
        return {};
#ifdef __APPLE__
    CFStringRef ref = CFStringCreateWithBytesNoCopy({}, (UInt8 *)fileName.data(),
        CFIndex(fileName.size()), kCFStringEncodingUTF8, FALSE, kCFAllocatorNull);
    string out(fileName.size() * 2, 0);
    CFStringGetFileSystemRepresentation(ref, out.data(), CFIndex(out.size()));
    CFRelease(ref);
    out.resize(strlen(out.c_str()));
#else
    f_string out = fs::u8path(fileName);
#endif
    return out;
}

/**
 * Decodes path from std lib path
 * @param localFileName path
 * @return decoded path
 */
string File::decodeName(const f_string_view &localFileName)
{
    if(localFileName.empty())
        return {};
#ifdef __APPLE__
    CFMutableStringRef ref = CFStringCreateMutable(nullptr, 0);
    CFStringAppendCString(ref, localFileName.data(), kCFStringEncodingUTF8);
    CFStringNormalize(ref, kCFStringNormalizationFormC);

    string out(localFileName.size() * 2, 0);
    CFStringGetCString(ref, out.data(), CFIndex(out.size()), kCFStringEncodingUTF8);
    CFRelease(ref);
    out.resize(strlen(out.c_str()));
#else
    string out = fs::path(localFileName).u8string();
#endif
    return out;
}

/**
 * Checks whether file exists and is type of file.
 *
 * @param path path to the file, which existence is checked.
 * @return returns true if the path is a file and it exists.
 */
bool File::fileExists(const string& path)
{
    f_statbuf fileInfo;
    return f_stat(encodeName(path).c_str(), &fileInfo) == 0 && (fileInfo.st_mode & S_IFMT) == S_IFREG;
}

#ifdef _WIN32
string File::dllPath(const string &dll)
{
#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
    HMODULE handle = GetModuleHandleW(fs::u8path(dll).c_str());
    wstring path(MAX_PATH, 0);
    DWORD size = GetModuleFileNameW(handle, path.data(), DWORD(path.size()));
    path.resize(size);
    return fs::path(path).parent_path().u8string() + "\\";
#else
    return "./";
#endif
}
#endif

/**
 * Returns last modified time
 *
 * @param path path which modified time will be checked.
 * @return returns given path modified time.
 */
time_t File::modifiedTime(const string &path)
{
    f_statbuf fileInfo;
    return f_stat(encodeName(path).c_str(), &fileInfo) ? time(nullptr) : fileInfo.st_mtime;
}

void File::updateModifiedTime(const string &path, time_t time)
{
    f_string _path = encodeName(path);
    f_utimbuf u_time { time, time };
    if(f_utime(_path.c_str(), &u_time))
        THROW("Failed to update file modified time.");
}

string File::fileExtension(const string &path)
{
    size_t pos = path.find_last_of('.');
    if(pos == string::npos)
        return {};
    string ext = path.substr(pos + 1);
    transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    return ext;
}

/**
 * Returns file size
 */
unsigned long File::fileSize(const string &path)
{
    f_statbuf fileInfo;
    return f_stat(encodeName(path).c_str(), &fileInfo) ? 0 : (unsigned long)fileInfo.st_size;
}

/**
 * Parses file path and returns file name from file full path.
 *
 * @param path full path of the file.
 * @return returns file name from the file full path in UTF-8.
 */
string File::fileName(const string& path)
{
    size_t pos = path.find_last_of("/\\");
    return pos == string::npos ? path : path.substr(pos + 1);
}

#ifdef __APPLE__
string File::frameworkResourcesPath(const string &name)
{
    string result(PATH_MAX, 0);
    CFStringRef identifier = CFStringCreateWithCString(nullptr, name.c_str(), kCFStringEncodingUTF8);
    if(CFBundleRef bundle = CFBundleGetBundleWithIdentifier(identifier))
    {
        if(CFURLRef url = CFBundleCopyResourcesDirectoryURL(bundle))
        {
            CFURLGetFileSystemRepresentation(url, TRUE, (UInt8 *)result.data(), CFIndex(result.size()));
            CFRelease(url);
        }
    }
    CFRelease(identifier);
    result.resize(strlen(result.c_str()));
    if(!result.empty()) result += "/";
    return result;
}
#endif

/**
 * Parses file path and returns directory from file full path.
 *
 * @param path full path of the file.
 * @return returns directory part of the file full path.
 */
string File::directory(const string& path)
{
    size_t pos = path.find_last_of("/\\");
    return pos == string::npos ? string() : path.substr(0, pos);
}

/**
 * Creates full path from directory name and relative path.
 *
 * @param directory directory path.
 * @param relativePath relative path.
 * @param unixStyle when set to <code>true</code> returns path with unix path separators,
 *        otherwise returns with operating system specific path separators.
 *        Default value is <code>false</code>.
 * @return returns full path.
 */
string File::path(string dir, string_view relativePath)
{
    if(!dir.empty() && (dir.back() == '/' || dir.back() == '\\'))
        dir.pop_back();

    string path = (dir + "/").append(relativePath);
#ifdef _WIN32
    replace(path.begin(), path.end(), '/', '\\');
#else
    replace(path.begin(), path.end(), '\\', '/');
#endif
    return path;
}

/**
 * @return returns temporary filename.
 */
string File::tempFileName()
{
#ifdef _WIN32
    // requires TMP environment variable to be set
    wchar_t *fileName = _wtempnam(nullptr, nullptr); // TODO: static buffer, not thread-safe
    if(!fileName)
        THROW("Failed to create a temporary file name.");
    string path = fs::path(fileName).u8string();
    free(fileName);
#else
#ifdef __APPLE__
    string path = File::path(env("TMPDIR"), "XXXXXX");
#else
    string path = "/tmp/XXXXXX";
#endif
    if(mkstemp(path.data()) == -1)
        THROW("Failed to create a temporary file name.");
#endif
    tempFiles.push(path);
    return path;
}

/**
 * Creates directory recursively. Also access rights can be omitted. Defaults are 700 in unix.
 *
 * @param path full path of the directory created.
 * @throws IOException exception is thrown if the directory creation failed.
 */
void File::createDirectory(const string& path)
{
    if(path.empty())
        THROW("Can not create directory with no name.");

    string dirPath = path;
    if(dirPath.back() == '/' || dirPath.back() == '\\')
        dirPath.pop_back();

    f_string _path = encodeName(dirPath);
    f_statbuf fileInfo;
    if(f_stat(_path.c_str(), &fileInfo) == 0 && (fileInfo.st_mode & S_IFMT) == S_IFDIR)
        return;
    createDirectory(directory(dirPath));

#ifdef _WIN32
    int result = _wmkdir(_path.c_str());
    if ( result )
        DEBUG("Creating directory '%s' failed with errno = %d", path.c_str(), errno);
    else
        DEBUG("Created directory '%s'", path.c_str());
#else
    int result = mkdir(_path.c_str(), S_IRWXU);
    DEBUG("Created directory '%s' with result = %d", path.c_str(), result);
#endif
    if(result)
        THROW("Failed to create directory '%s'", path.c_str());
}

string File::digidocppPath()
{
#ifdef _WIN32
    PWSTR knownFolder {};
    if(SHGetKnownFolderPath(FOLDERID_RoamingAppData, KF_FLAG_CREATE, nullptr, &knownFolder) != S_OK)
        THROW("Failed to get home directory");
    string appData = (fs::path(knownFolder) / "digidocpp").u8string();
    CoTaskMemFree(knownFolder);
    return appData;
#elif defined(ANDROID)
    return path(env("HOME"), ".digidocpp");
#else
    string buf(sysconf(_SC_GETPW_R_SIZE_MAX), 0);
    struct passwd pwbuf {};
    struct passwd *pw {};
    if(getpwuid_r(geteuid(), &pwbuf, buf.data(), buf.size(), &pw) != 0 || !pw)
        THROW("Failed to get home directory");
    return path(pw->pw_dir, ".digidocpp");
#endif
}

/**
 * Returns true if the path is relative
 *
 * @return returns true if the path is relative
 */
bool File::isRelative(const string &path)
{
    f_string _path = encodeName(path);
    if(_path.empty()) return true;
    if(_path[0] == '/') return false;
#ifdef _WIN32
    // drive, e.g. "a:", or UNC root, e.q. "//"
    if( _path.length() >= 2 &&
        ((iswalpha(_path[0]) && _path[1] == ':') ||
         (_path[0] == '/' && _path[1] == '/')) )
        return false;
#endif
    return true;
}

/**
 * Constructs the full file path in the format "file:///fullpath" in URI encoding. 
 *
 * @param fullDirectory full directory path to the relativeFilePath
 * @param relativeFilePath file name to be appended to the full path
 * @return full file path in the format "file:///fullpath" in URI encoding.
 */
string File::fullPathUrl(const string &path)
{
#ifdef _WIN32
    // Under windows replace the path delimiters
    string result = path;
    replace(result.begin(), result.end(), '\\', '/');
    return "file:///" + File::toUri(result);
#else
    return "file://" + File::toUri(path);
#endif
}

/**
 * Tries to delete all temporary files and directories whose names were handled out with tempFileName, tempDirectory and createTempDirectory.
 * The deletion of directories is recursive.
 */
void File::deleteTempFiles()
{
    while(!tempFiles.empty())
    {
        if(!removeFile(tempFiles.top()))
            WARN( "Tried to remove the temporary file or directory '%s', but failed.", tempFiles.top().c_str() );
        tempFiles.pop();
    }
}

bool File::removeFile(const string &path)
{
#ifdef _WIN32
    return _wremove(fs::u8path(path).c_str()) == 0;
#else
    return remove(encodeName(path).c_str()) == 0;
#endif
}

/**
 * Helper method for converting strings with non-ascii characters to the URI format (%HH for each non-ascii character).
 *
 * Not converting:
 * (From RFC 2396 "URI Generic Syntax")
 * reserved = ";" | "/" | "?" | ":" | "@" | "&" | "=" | "+" | "$" | ","
 * mark     = "-" | "_" | "." | "!" | "~" | "*" | "'" | "(" | ")"
 * @param str_in the string to be converted
 * @return the string converted to the URI format
 */
string File::toUri(const string &path)
{
    static const string legal_chars = "-_.!~*'();/?:@&=+$,";
    static const locale locC("C");
    ostringstream dst;
    for(const char &i: path)
    {
        if(isalnum(i, locC) || legal_chars.find(i) != string::npos)
            dst << i;
        else
            dst << '%' << hex << uppercase << (static_cast<int>(i) & 0xFF);
    }
    return dst.str();
}

/**
 * Helper method for converting strings with non-ascii characters to the URI format (%HH for each non-ascii character).
 *
 * Not converting:
 * (From RFC  RFC 3986 "URI Generic Syntax")
 * unreserved    = ALPHA / DIGIT / “-” / “.” / “_” / “~”
 * gen-delims = “:” / “/” / “?” / “#” / “[” / “]” / “@”
 * sub-delims    = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
 *
 *  3.3. Path
 * pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
 * We also encode sub-delims and ":" "@" to be safe
 *
 * @param str_in the string to be converted
 * @return the string converted to the URI format
 */
string File::toUriPath(const string &path)
{
    static const string unreserved = "-._~/";
    //static string sub-delims = "!$&'()*+,;="
    static const locale locC("C");
    ostringstream dst;
    for(const char &i: path)
    {
        if(isalnum(i, locC) || unreserved.find(i) != string::npos)
            dst << i;
        else
            dst << '%' << hex << uppercase << (static_cast<int>(i) & 0xFF);
    }
    return dst.str();
}

string File::fromUriPath(const string &path)
{
    string ret;
    char data[] = "00";
    for(string::const_iterator i = path.begin(); i != path.end(); ++i)
    {
        if(*i == '%' && (distance(i, path.end()) > 2) && isxdigit(*(i+1)) && isxdigit(*(i+2)))
        {
            data[0] = *(++i);
            data[1] = *(++i);
            ret += static_cast<char>(strtoul(data, nullptr, 16));
        }
        else {
            ret += *i;
        }
    }
    return ret;
}

vector<unsigned char> File::hexToBin(const string &in)
{
    vector<unsigned char> out;
    char data[] = "00";
    for(string::const_iterator i = in.cbegin(); distance(i, in.cend()) >= 2;)
    {
        data[0] = *(i++);
        data[1] = *(i++);
        out.push_back(static_cast<unsigned char>(strtoul(data, nullptr, 16)));
    }
    return out;
}
