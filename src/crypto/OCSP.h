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

#include "util/memory.h"

#include <string>
#include <vector>

using OCSP_RESPONSE = struct ocsp_response_st;
using OCSP_BASICRESP = struct ocsp_basic_response_st;

namespace digidoc
{
    class X509Cert;
    /**
     * Implements OCSP request to the OCSP server. This class can be used to
     * check whether the certificate is valid or not.
     */
    class OCSP
    {

      public:
          OCSP(const X509Cert &cert, const X509Cert &issuer, const std::string &userAgent = {});
          inline OCSP(const std::vector<unsigned char> &data): OCSP(data.data(), data.size()) {}
          OCSP(const unsigned char *data = nullptr, size_t size = 0);

          std::vector<unsigned char> nonce() const;
          tm producedAt() const;
          X509Cert responderCert() const;
          void verifyResponse(const X509Cert &cert) const;

          operator std::vector<unsigned char>() const;

      private:
          bool compareResponderCert(const X509Cert &cert) const;

          unique_free_t<OCSP_RESPONSE> resp;
          unique_free_t<OCSP_BASICRESP> basic;
    };
}
