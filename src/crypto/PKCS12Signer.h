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
    struct PKCS12SignerPrivate;
    /**
     * Implements <code>Signer</code> interface for signing with RSA private key.
     *
     * @author Janari Põld
     */
    class PKCS12Signer : public Signer
    {

      public:
          PKCS12Signer(const std::string &pkcs12, const std::string &pass);
          virtual ~PKCS12Signer();
          X509Cert cert() const;
          void sign(const std::string &method, const std::vector<unsigned char> &digest,
                    std::vector<unsigned char> &signature);

      private:
          PKCS12SignerPrivate *d;

    };
}
