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

#define URI_SHA1 "http://www.w3.org/2000/09/xmldsig#sha1"
#define URI_SHA224 "http://www.w3.org/2001/04/xmldsig-more#sha224"
#define URI_SHA256 "http://www.w3.org/2001/04/xmlenc#sha256"
#define URI_SHA384 "http://www.w3.org/2001/04/xmldsig-more#sha384"
#define URI_SHA512 "http://www.w3.org/2001/04/xmlenc#sha512"

#define OID_SHA1 "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"
#define OID_SHA224 "\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c"
#define OID_SHA256 "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
#define OID_SHA384 "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30"
#define OID_SHA512 "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40"

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
    class DigestPrivate;
    class Digest
    {
      public:
          Digest(const std::string &uri = "");
          ~Digest();
          void reset(const std::string &uri = "");
          void update(const std::vector<unsigned char> &data);
          void update(const unsigned char *data, unsigned long length);
          std::vector<unsigned char> result() const;
          std::string uri() const;

          static std::string toRsaUri(const std::string &uri);
          static std::string toEcUri(const std::string &uri);
          static int toMethod(const std::string &uri);

      private:
          DISABLE_COPY(Digest);
          DigestPrivate *d;
    };

}
