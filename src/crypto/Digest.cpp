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

#include "Digest.h"

#include "Conf.h"
#include "crypto/OpenSSLHelpers.h"

#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

using namespace std;

#if OPENSSL_VERSION_NUMBER < 0x10010000L
static void X509_SIG_get0(const X509_SIG *sig, const X509_ALGOR **palg, const ASN1_OCTET_STRING **pdigest)
{
    if(palg) *palg = sig->algor;
    if(pdigest) *pdigest = sig->digest;
}
#endif

namespace digidoc
{
class DigestPrivate: public vector<unsigned char>
{
public:
    DigestPrivate(): method(0) {}
    union {
        SHA_CTX sha1;
        SHA256_CTX sha256;
        SHA512_CTX sha512;
    };
    int method;
};
}

using namespace digidoc;

/**
 * Initializes OpenSSL digest calculator.
 *
 * @param uri digest method URI (e.g. 'http://www.w3.org/2000/09/xmldsig#sha1' for SHA1).
 * @throws IOException throws exception if the digest calculator initialization failed.
 */
Digest::Digest(const string &uri)
    : d( new DigestPrivate )
{
    reset(uri);
}

/**
 * Destroys OpenSSL digest calculator.
 */
Digest::~Digest()
{
    delete d;
}

vector<unsigned char> Digest::addDigestInfo(const vector<unsigned char> &digest, const string &uri)
{
    vector<unsigned char> result = digest;
    vector<unsigned char> oid;
    switch(toMethod(uri))
    {
    case NID_sha1: oid = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14}; break;
    case NID_sha224: oid = {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c}; break;
    case NID_sha256: oid = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}; break;
    case NID_sha384: oid = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30}; break;
    case NID_sha512: oid = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40}; break;
    default: break;
    }
    if(!oid.empty())
        result.insert(result.begin(), oid.begin(), oid.end());
    return result;
}

vector<unsigned char> Digest::digestInfoDigest(const std::vector<unsigned char> &digest)
{
    const unsigned char *p = digest.data();
    SCOPE(X509_SIG, sig, d2i_X509_SIG(NULL, &p, (long)digest.size()));
    if(!sig)
        return vector<unsigned char>();
    const ASN1_OCTET_STRING *value = nullptr;
    X509_SIG_get0(sig.get(), nullptr, &value);
    return vector<unsigned char>(value->data, value->data + value->length);
}

string Digest::digestInfoUri(const std::vector<unsigned char> &digest)
{
    const unsigned char *p = digest.data();
    SCOPE(X509_SIG, sig, d2i_X509_SIG(NULL, &p, (long)digest.size()));
    if(!sig)
        return string();
    const X509_ALGOR *algor = nullptr;
    X509_SIG_get0(sig.get(), &algor, nullptr);
    switch(OBJ_obj2nid(algor->algorithm))
    {
    case NID_sha1:  return URI_SHA1;
    case NID_sha224: return URI_SHA224;
    case NID_sha256: return URI_SHA256;
    case NID_sha384: return URI_SHA384;
    case NID_sha512: return URI_SHA512;
    default: return string();
    }
}

/**
 * return returns digest method URI.
 * @see Digest::toMethod(const std::string& uri)
 */
string Digest::uri() const
{
    switch(d->method)
    {
    case NID_sha1: return URI_SHA1;
    case NID_sha224: return URI_SHA224;
    case NID_sha256: return URI_SHA256;
    case NID_sha384: return URI_SHA384;
    case NID_sha512: return URI_SHA512;
    default: return "";
    }
}

/**
 *
 */
void Digest::reset(const string &uri)
{
    if(uri.empty() && Conf::instance()->digestUri() == URI_SHA1)
        THROW("Unsupported digest method");

    int result = 0;
    switch(d->method = toMethod(uri.empty() ? Conf::instance()->digestUri() : uri))
    {
    case NID_sha1: result = SHA1_Init(&d->sha1); break;
    case NID_sha224: result = SHA224_Init(&d->sha256); break;
    case NID_sha256: result = SHA256_Init(&d->sha256); break;
    case NID_sha384: result = SHA384_Init(&d->sha512); break;
    case NID_sha512: result = SHA512_Init(&d->sha512); break;
    default: break;
    }
    d->clear();
    if(result != 1)
        THROW_CAUSE(OpenSSLException(), "Failed to initialize %s digest calculator", uri.c_str());
}

/**
 * Converts digest method URI to OpenSSL method id (e.g. 'http://www.w3.org/2000/09/xmldsig#sha1' to NID_sha1,
 * see openssl/obj_mac.h)
 * For available method URIs see:
 * <li>
 *   <ul><b>W3C XML Encryption Syntax and Processing</b> (10 December 2005) http://www.w3.org/TR/xmlenc-core/</ul>
 *   <ul><b>RFC 4051</b> http://www.ietf.org/rfc/rfc4051.txt</ul>
 * </li>
 *
 * @param uri digest method URI (e.g. 'http://www.w3.org/2000/09/xmldsig#sha1' for SHA1).
 * @return returns digest OpenSSL method id.
 * @throws IOException throws exception if digest method is not supported.
 */
int Digest::toMethod(const string &uri)
{
    if(uri == URI_SHA1 || uri == URI_RSA_SHA1 || uri == URI_ECDSA_SHA1) return NID_sha1;
    if(uri == URI_SHA224 || uri == URI_RSA_SHA224 || uri == URI_ECDSA_SHA224) return NID_sha224;
    if(uri == URI_SHA256 || uri == URI_RSA_SHA256 || uri == URI_ECDSA_SHA256) return NID_sha256;
    if(uri == URI_SHA384 || uri == URI_RSA_SHA384 || uri == URI_ECDSA_SHA384) return NID_sha384;
    if(uri == URI_SHA512 || uri == URI_RSA_SHA512 || uri == URI_ECDSA_SHA512) return NID_sha512;
    THROW( "Digest method URI '%s' is not supported.", uri.c_str() );
    return 0;
}

string Digest::toRsaUri(const string &uri)
{
    if(uri == URI_SHA1) return URI_RSA_SHA1;
    if(uri == URI_SHA224) return URI_RSA_SHA224;
    if(uri == URI_SHA256) return URI_RSA_SHA256;
    if(uri == URI_SHA384) return URI_RSA_SHA384;
    if(uri == URI_SHA512) return URI_RSA_SHA512;
    return "";
}

string Digest::toEcUri(const string &uri)
{
    if(uri == URI_SHA1) return URI_ECDSA_SHA1;
    if(uri == URI_SHA224) return URI_ECDSA_SHA224;
    if(uri == URI_SHA256) return URI_ECDSA_SHA256;
    if(uri == URI_SHA384) return URI_ECDSA_SHA384;
    if(uri == URI_SHA512) return URI_ECDSA_SHA512;
    return "";
}

/**
 * Add data for digest calculation.
 *
 * @param data data to add for digest calculation.
 * @throws IOException throws exception if SHA1 update failed.
 * @see update(const unsigned char* data, unsigned long length)
 */
void Digest::update(const vector<unsigned char> &data)
{
    update(data.data(), (unsigned int)data.size());
}

/**
 * Add data for digest calculation. After calling <code>getDigest()</code> SHA context
 * is uninitialized and this method should not be called.
 *
 * @param data data to add for digest calculation.
 * @param length length of the data.
 * @throws IOException throws exception if update failed.
 * @see getDigest()
 */
void Digest::update(const unsigned char *data, unsigned long length)
{
    if(!data)
        THROW("Can not update digest value from NULL pointer.");

    if(!d->empty())
        THROW("Digest is already finalized, can not update it.");

    int result = 1;
    switch(d->method)
    {
    case NID_sha1: result = SHA1_Update(&d->sha1, data, length); break;
    case NID_sha224: result = SHA224_Update(&d->sha256, data, length); break;
    case NID_sha256: result = SHA256_Update(&d->sha256, data, length); break;
    case NID_sha384: result = SHA384_Update(&d->sha512, data, length); break;
    case NID_sha512: result = SHA512_Update(&d->sha512, data, length); break;
    default: break;
    }
    if(result != 1)
        THROW_CAUSE(OpenSSLException(), "Failed to update %s digest value", uri().c_str());
}

/**
 * Calculate message digest. SHA context will be invalid after this call.
 * For calculating an other digest you must create new SHA1Digest class.
 *
 * @return returns the calculated digest.
 * @throws IOException throws exception if update failed.
 */
vector<unsigned char> Digest::result() const
{
    if(!d->empty())
        return *d;

    int result = 0;
    switch(d->method)
    {
    case NID_sha1:
        d->resize(SHA_DIGEST_LENGTH);
        result = SHA1_Final(d->data(), &d->sha1);
        break;
    case NID_sha224:
        d->resize(SHA224_DIGEST_LENGTH);
        result = SHA224_Final(d->data(), &d->sha256);
        break;
    case NID_sha256:
        d->resize(SHA256_DIGEST_LENGTH);
        result = SHA256_Final(d->data(), &d->sha256);
        break;
    case NID_sha384:
        d->resize(SHA384_DIGEST_LENGTH);
        result = SHA384_Final(d->data(), &d->sha512);
        break;
    case NID_sha512:
        d->resize(SHA512_DIGEST_LENGTH);
        result = SHA512_Final(d->data(), &d->sha512);
        break;
    default: break;
    }
    if(result != 1)
        THROW_CAUSE(OpenSSLException(), "Failed to create %s digest", uri().c_str());

    return *d;
}
