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

#include "../Exception.h"

#include "X509Cert.h"

#ifdef WIN32 //hack for win32 build
#undef OCSP_REQUEST
#undef OCSP_RESPONSE
#endif
#include <openssl/ocsp.h>

namespace digidoc
{
    /**
     * OCSP exception implementation. Thrown if OCSP response is not valid or
     * OCSP response status code is not Successful (0x00). OCSP status code can be
     * accessed with method <code>getResponseStatusMessage()</code>. For example
     * if the status code is 0x03 (TryLater) the OCSP request can be be made
     * again (e.g. the OCSP server could be busy at the time).
     *
     * @author Janari Põld
     */


    class X509Cert;
    /**
     * Implements OCSP request to the OCSP server. This class can be used to
     * check whether the certificate is valid or not.
     *
     * If <code>certStore</code> and/or <code>ocspCerts</code> is set, the
     * OCSP response certificate is checked, whether it comes from the correct
     * OCSP server or not.
     *
     * If <code>signCert</code> and <code>signKey</code> is set the OCSP request
     * is signed with the certificate provided.
     *
     * @author Janari Põld
     */
    class OCSP
    {

      public:
          OCSP(const X509Cert &cert, const X509Cert &issuer,
               const std::vector<unsigned char> &nonce, const std::string &useragent = "");
          OCSP(const std::vector<unsigned char> &ocspResponseDER);
          ~OCSP();

          std::vector<unsigned char> nonce() const;
          std::string producedAt() const;
          bool compareResponderCert(const X509Cert &cert);
          X509Cert responderCert() const;
          std::vector<unsigned char> toDer() const;
          void verifyResponse(const X509Cert &cert) const;

      private:
          OCSP_REQUEST* createRequest(OCSP_CERTID *certId, const std::vector<unsigned char> &nonce);
          OCSP_RESPONSE* sendRequest(const std::string &url, OCSP_REQUEST *req, const std::string &useragent);

          OCSP_RESPONSE *resp;
          OCSP_BASICRESP *basic;
    };
}
