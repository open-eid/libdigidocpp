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

#include "Signer.h"

namespace digidoc
{
    class DIGIDOCPP_EXPORT WinSigner : public Signer
    {

      public:
          WinSigner(const std::string &pin = {}, bool selectFirst = false);
          ~WinSigner() final;
          void setPin(const std::string &pin);
          void setSelectFirst(bool first);
          void setThumbprint(const std::vector<unsigned char> &thumbprint);

      private:
          X509Cert cert() const final;
          std::string method() const final;
          std::vector<unsigned char> sign(const std::string &method, const std::vector<unsigned char> &digest) const final;

          DISABLE_COPY(WinSigner);
          class Private;
          Private *d;
    };
}
