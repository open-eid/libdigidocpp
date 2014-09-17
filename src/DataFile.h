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
#include <istream>
#include <string>
#include <vector>

namespace digidoc
{
    class DataFilePrivate;
    class Digest;
    class EXP_DIGIDOC DataFile
    {

      public:
          std::string id() const;
          std::string fileName() const;
          unsigned long fileSize() const;
          std::string mediaType() const;

          std::vector<unsigned char> calcDigest(const std::string &method) const;
          void saveAs(std::ostream &os) const;
          void saveAs(const std::string& path) const;

      private:
          DataFile(std::istream *is, const std::string &filename, const std::string &mediatype,
                   const std::string &id = "", const std::vector<unsigned char> &digestValue = std::vector<unsigned char>());
          void calcDigest(Digest *method) const;

          std::shared_ptr<DataFilePrivate> d;

          friend class BDoc;
          friend class DDoc;
          friend class URIResolver;
          friend class SignatureA;
    };
}
