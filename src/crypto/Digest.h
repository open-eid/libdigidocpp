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

#include "../Exports.h"

#include <string>
#include <vector>

#define URI_SHA1 "http://www.w3.org/2000/09/xmldsig#sha1"
#define URI_SHA224 "http://www.w3.org/2001/04/xmldsig-more#sha224"
#define URI_SHA256 "http://www.w3.org/2001/04/xmlenc#sha256"
#define URI_SHA384 "http://www.w3.org/2001/04/xmldsig-more#sha384"
#define URI_SHA512 "http://www.w3.org/2001/04/xmlenc#sha512"

#define URI_RSA_SHA1 "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
#define URI_RSA_SHA224 "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224"
#define URI_RSA_SHA256 "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
#define URI_RSA_SHA384 "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
#define URI_RSA_SHA512 "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"

#define URI_ECDSA_SHA1 "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"
#define URI_ECDSA_SHA224 "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224"
#define URI_ECDSA_SHA256 "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
#define URI_ECDSA_SHA384 "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
#define URI_ECDSA_SHA512 "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"

namespace digidoc
{
    /**
     * Digest calculation interface.
     */
    class Digest
    {
      public:
          Digest(const std::string &uri = std::string());
          ~Digest();
          void reset(const std::string &uri = std::string());
          void update(const std::vector<unsigned char> &data);
          void update(const unsigned char *data, size_t length);
          std::vector<unsigned char> result() const;
          std::string uri() const;

          static std::string toRsaUri(const std::string &uri);
          static std::string toEcUri(const std::string &uri);
          static int toMethod(const std::string &uri);
          static std::string toUri(int nid);
          static std::vector<unsigned char> addDigestInfo(const std::vector<unsigned char> &digest, const std::string &uri);
          static std::vector<unsigned char> digestInfoDigest(const std::vector<unsigned char> &digest);
          static std::string digestInfoUri(const std::vector<unsigned char> &digest);

      private:
          DISABLE_COPY(Digest);
          class Private;
          Private *d;
    };

}
