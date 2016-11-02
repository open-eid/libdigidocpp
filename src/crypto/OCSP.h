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

#include <memory>
#include <string>
#include <vector>

typedef struct ocsp_response_st OCSP_RESPONSE;
typedef struct ocsp_basic_response_st OCSP_BASICRESP;
typedef struct ocsp_cert_id_st OCSP_CERTID;
typedef struct ocsp_request_st OCSP_REQUEST;

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
          OCSP(const X509Cert &cert, const X509Cert &issuer,
               const std::vector<unsigned char> &nonce, const std::string &useragent = "");
          OCSP(const std::vector<unsigned char> &data);

          std::vector<unsigned char> nonce() const;
          std::string producedAt() const;
          bool compareResponderCert(const X509Cert &cert) const;
          X509Cert responderCert() const;
          std::vector<unsigned char> toDer() const;
          void verifyResponse(const X509Cert &cert) const;

      private:
          OCSP_REQUEST* createRequest(OCSP_CERTID *certId, const std::vector<unsigned char> &nonce);
          OCSP_RESPONSE* sendRequest(const std::string &url, OCSP_REQUEST *req, const std::string &useragent);

          std::shared_ptr<OCSP_RESPONSE> resp;
          std::shared_ptr<OCSP_BASICRESP> basic;
    };
}
