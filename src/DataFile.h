// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

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
