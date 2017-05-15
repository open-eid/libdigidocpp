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

#include "X509Cert.h"

namespace digidoc
{
    /**
     * Wrapper for RSA crypto function in OpenSSL. Currently implemented RSA signature
     * verification and signing with private RSA key.
     *
     * @author Janari Põld
     */
    class X509Crypto
    {

      public:
          X509Crypto(const X509Cert &cert);

          bool compareIssuerToDer(const std::vector<unsigned char> &issuer) const;
          int compareIssuerToString(const std::string &name) const;
          bool isRSAKey() const;

          bool verify(const std::string &method, const std::vector<unsigned char> &digest,
                      const std::vector<unsigned char> &signature);

      private:
          X509Cert cert;

    };
}
