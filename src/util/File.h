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

#pragma once

#include "../Exception.h"

#include <stack>

#ifdef _WIN32
using f_string = std::wstring;
#else
using f_string = std::string;
#endif

namespace digidoc
{
    namespace util
    {

        /**
         * Implements common file-system operations for current platform
         */
        class File
        {
          public:
              static std::string confPath();
              static std::string cwd();
              static std::string env(const std::string &varname);
              static bool fileExists(const std::string& path);
              static f_string encodeName(const std::string &fileName);
              static std::string decodeName(const f_string &localFileName);
              static bool isRelative(const std::string &path);
              static struct tm modifiedTime(const std::string &path);
              static std::string fileExtension(const std::string &path);
              static unsigned long fileSize(const std::string &path);
              static std::string fileName(const std::string& path);
              static std::string directory(const std::string& path);
              static std::string path(const std::string& directory, const std::string& relativePath);
              static std::string fullPathUrl(const std::string &path);
              static std::string tempFileName();
              static void createDirectory(const std::string& path);
              static std::vector<std::string> listFiles(const std::string& directory);
              static void deleteTempFiles();
              static bool removeFile(const std::string &path);
              static std::string toUri(const std::string &path);
              static std::string toUriPath(const std::string &path);
              static std::string fromUriPath(const std::string &path);
              static std::vector<unsigned char> hexToBin(const std::string &in);
#ifdef __APPLE__
              static std::string frameworkResourcesPath(const std::string &name);
#endif
#ifdef _WIN32
              static std::string dllPath(const std::string &dll);
#endif

        private:
#if !defined(_WIN32) && !defined(__APPLE__)
              static std::string convertUTF8(const std::string &str_in, bool to_UTF);
#endif
              static std::stack<std::string> tempFiles;
        };

    }
}
