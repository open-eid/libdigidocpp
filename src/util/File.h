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
              static std::string decodeName(const std::filesystem::path &path);
              static std::string digidocppPath();
              static std::filesystem::path encodeName(std::string_view fileName);
              static time_t modifiedTime(const std::string &path);
              static bool fileExists(const std::string& path);
              static bool fileExtension(std::string_view path, std::initializer_list<std::string_view> list);
              static auto fileSize(const std::filesystem::path &path) noexcept
              {
                  std::error_code ec;
                  auto size = std::filesystem::file_size(path, ec);
                  return ec ? 0 : size;
              }
              static constexpr std::string_view fileName(std::string_view path) noexcept
              {
                  auto pos = path.find_last_of("/\\");
                  return pos == std::string_view::npos ? path : path.substr(pos + 1);
              }
              static constexpr std::string_view directory(std::string_view path) noexcept
              {
                  auto pos = path.find_last_of("/\\");
                  return pos == std::string_view::npos ? std::string_view() : path.substr(0, pos);
              }
              static std::string path(std::string dir, std::string_view relativePath);
              static std::filesystem::path tempFileName();
              static void createDirectory(std::string_view path);
              static std::string toUriPath(const std::string &path);
              static std::string fromUriPath(std::string_view path);
              static std::vector<unsigned char> hexToBin(std::string_view in);
        };

    }
}
