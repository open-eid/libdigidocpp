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
     * ZIP file implementation of the ISerialize interface. Saves files to ZIP file
     * and extracts the ZIP file on demand. Uses ZLib to implement ZIP file operations.
     */
    class ZipSerialize
    {
      public:
          struct Properties { std::string comment; time_t time; unsigned long size; };
          enum Flags { NoFlags = 0, DontCompress = 1 };
          ZipSerialize(std::string path, bool create);
          ~ZipSerialize();

          std::vector<std::string> list() const;
          std::unique_ptr<std::istream> stream(const std::string &file) const;
          void extract(const std::string &file, std::ostream &os) const;
          void addFile(const std::string &containerPath, std::istream &is, const Properties &prop, Flags flags = NoFlags);
          Properties properties(const std::string &file) const;

      private:
          DISABLE_COPY(ZipSerialize);
          class Private;
          std::unique_ptr<Private> d;
    };
}
