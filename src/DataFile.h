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

namespace digidoc
{
    class DIGIDOCPP_EXPORT DataFile
    {

      public:
          virtual ~DataFile();
          virtual std::string id() const = 0;
          virtual std::string fileName() const = 0;
          virtual unsigned long fileSize() const = 0;
          virtual std::string mediaType() const = 0;

          virtual std::vector<unsigned char> calcDigest(const std::string &method) const = 0;
          virtual void saveAs(std::ostream &os) const = 0;
          virtual void saveAs(const std::string& path) const = 0;

      protected:
          DataFile();

      private:
          DISABLE_COPY(DataFile);
    };
}
