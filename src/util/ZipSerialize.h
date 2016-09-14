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

#include <string>
#include <vector>
#ifdef ANDROID
#include <time.h>
#endif

namespace digidoc
{
    /**
     * ZIP file implementation of the ISerialize interface. Saves files to ZIP file
     * and extracts the ZIP file on demand. Uses ZLib to implement ZIP file operations.
     *
     * @author Janari Põld
     */
    class ZipSerializePrivate;
    class ZipSerialize
    {
      public:
          struct Properties { std::string comment; tm time; };
          enum {
              DontCompress = 1
          };
          ZipSerialize(const std::string &path, bool create);
          ~ZipSerialize();

          std::vector<std::string> list() const;
          void extract(const std::string &file, std::ostream &os) const;
          void addFile(const std::string &containerPath, std::istream &is, const Properties &prop, unsigned int flags = 0);
          Properties properties(const std::string &file) const;
          void save();

      private:
          DISABLE_COPY(ZipSerialize);
          ZipSerializePrivate *d;
    };
}
