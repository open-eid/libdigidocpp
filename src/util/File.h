// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "../Exception.h"

#include <filesystem>

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
              static bool fileExists(const std::string& path);
              static bool fileExtension(std::string_view path, std::initializer_list<std::string_view> list);
              static unsigned long fileSize(const std::filesystem::path &path) noexcept;
              static std::string_view fileName(std::string_view path) noexcept;
              static std::string directory(const std::string& path);
              static std::string path(std::string dir, std::string_view relativePath);
              static std::filesystem::path tempFileName();
              static void createDirectory(std::string path);
              static std::string toUriPath(const std::string &path);
              static std::string fromUriPath(std::string_view path);
              static std::vector<unsigned char> hexToBin(std::string_view in);

        private:
#ifdef _WIN32
              static std::string dllPath(std::string_view dll);
#endif
#ifdef __APPLE__
              static std::string frameworkResourcesPath(std::string_view name);
#endif
        };

    }
}
