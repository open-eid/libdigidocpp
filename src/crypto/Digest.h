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

#include <memory>
#include <string>
#include <vector>

#define URI_SHA1 "http://www.w3.org/2000/09/xmldsig#sha1"
#define URI_SHA224 "http://www.w3.org/2001/04/xmldsig-more#sha224"
#define URI_SHA256 "http://www.w3.org/2001/04/xmlenc#sha256"
#define URI_SHA384 "http://www.w3.org/2001/04/xmldsig-more#sha384"
#define URI_SHA512 "http://www.w3.org/2001/04/xmlenc#sha512"
#define URI_SHA3_224 "http://www.w3.org/2007/05/xmldsig-more#sha3-224"
#define URI_SHA3_256 "http://www.w3.org/2007/05/xmldsig-more#sha3-256"
#define URI_SHA3_384 "http://www.w3.org/2007/05/xmldsig-more#sha3-384"
#define URI_SHA3_512 "http://www.w3.org/2007/05/xmldsig-more#sha3-512"

#define URI_RSA_SHA1 "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
#define URI_RSA_SHA224 "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224"
#define URI_RSA_SHA256 "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
#define URI_RSA_SHA384 "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
#define URI_RSA_SHA512 "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"

#define URI_RSA_PSS_SHA224 "http://www.w3.org/2007/05/xmldsig-more#sha224-rsa-MGF1"
#define URI_RSA_PSS_SHA256 "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"
#define URI_RSA_PSS_SHA384 "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1"
#define URI_RSA_PSS_SHA512 "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1"
#define URI_RSA_PSS_SHA3_224 "http://www.w3.org/2007/05/xmldsig-more#sha3-224-rsa-MGF1"
#define URI_RSA_PSS_SHA3_256 "http://www.w3.org/2007/05/xmldsig-more#sha3-256-rsa-MGF1"
#define URI_RSA_PSS_SHA3_384 "http://www.w3.org/2007/05/xmldsig-more#sha3-384-rsa-MGF1"
#define URI_RSA_PSS_SHA3_512 "http://www.w3.org/2007/05/xmldsig-more#sha3-512-rsa-MGF1"

#define URI_ECDSA_SHA1 "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"
#define URI_ECDSA_SHA224 "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224"
#define URI_ECDSA_SHA256 "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
#define URI_ECDSA_SHA384 "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
#define URI_ECDSA_SHA512 "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"

#ifdef LIBRESSL_VERSION_NUMBER
using EVP_MD_CTX = struct env_md_ctx_st;
#else
using EVP_MD_CTX = struct evp_md_ctx_st;
#endif

namespace digidoc
{
    /**
     * Digest calculation interface.
     */
    class Digest
    {
      public:
          Digest(std::string_view uri = {});
          ~Digest();
          void update(const unsigned char *data, size_t length);
          std::vector<unsigned char> result(const std::vector<unsigned char> &data);
          std::vector<unsigned char> result() const;
          std::string uri() const;

          static bool isRsaPssUri(std::string_view uri);
          static std::string toRsaUri(const std::string &uri);
          static std::string toRsaPssUri(std::string uri);
          static std::string toEcUri(const std::string &uri);
          static int toMethod(std::string_view uri);
          static std::string toUri(int nid);
          static std::vector<unsigned char> addDigestInfo(std::vector<unsigned char> digest, std::string_view uri);
          static std::vector<unsigned char> digestInfoDigest(const std::vector<unsigned char> &digest);
          static std::string digestInfoUri(const std::vector<unsigned char> &digest);

      private:
          DISABLE_COPY(Digest);
          std::unique_ptr<EVP_MD_CTX, void (*)(EVP_MD_CTX*)> d;
    };

}
