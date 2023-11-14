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

#include <filesystem>
#include <stack>

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
              static std::string digidocppPath();
              static std::filesystem::path encodeName(std::string_view fileName);
              static time_t modifiedTime(const std::string &path);
              static void updateModifiedTime(const std::string &path, time_t time);
              static bool fileExists(const std::string& path);
              static bool fileExtension(std::string_view path, std::initializer_list<std::string_view> list);
              static unsigned long fileSize(const std::string &path);
              static std::string fileName(const std::string& path);
              static std::string directory(const std::string& path);
              static std::string path(std::string dir, std::string_view relativePath);
              static std::string fullPathUrl(std::string path);
              static std::filesystem::path tempFileName();
              static void createDirectory(std::string path);
              static void deleteTempFiles();
              static bool removeFile(const std::string &path);
              static std::string toUri(const std::string &path);
              static std::string toUriPath(const std::string &path);
              static std::string fromUriPath(const std::string &path);
              static std::vector<unsigned char> hexToBin(const std::string &in);
#ifdef _WIN32
              static std::string dllPath(std::string_view dll);
#endif

        private:
#ifdef __APPLE__
              static std::string frameworkResourcesPath(std::string_view name);
#endif
              static std::stack<std::filesystem::path> tempFiles;
        };

    }
}
