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

#include "Exports.h"

#include <memory>
#include <string>
#include <vector>

namespace digidoc
{
    /**
     * Saves files to ZIP file and extracts the ZIP file on demand. Uses ZLib to implement ZIP file operations.
     */
    class ZipSerialize
    {
      public:
          struct Write {
              void operator ()(const void *data, size_t size) const;
              template<class T>
              constexpr void operator ()(const T &data) const
              {
                  operator ()(data.data(), data.size());
              }
              std::unique_ptr<void, int (*)(void*)> d;
          };

          struct Properties {
              std::string comment;
              time_t time;
              unsigned long size;
          };

          ZipSerialize(const std::string &path, bool create);

          std::vector<std::string> list() const;
          template<class T>
          T extract(std::string_view file) const;
          Write addFile(std::string_view containerPath, const Properties &prop, bool compress = true) const;
          Properties properties(const std::string &file) const;

      private:
          std::unique_ptr<void, int(*)(void*)> d;
    };

    extern template std::fstream ZipSerialize::extract<std::fstream>(std::string_view file) const;
    extern template std::stringstream ZipSerialize::extract<std::stringstream>(std::string_view file) const;
}
