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

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <array>

using namespace std;
using namespace digidoc;

/**
 * Initializes OpenSSL digest calculator.
 *
 * @param uri digest method URI (e.g. 'http://www.w3.org/2001/04/xmlenc#sha256' for SHA256).
 * @throws Exception throws exception if the digest calculator initialization failed.
 */
Digest::Digest(string_view uri)
    : d(SCOPE_PTR(EVP_MD_CTX, EVP_MD_CTX_new()))
{
    if(uri.empty() && Conf::instance()->digestUri() == URI_SHA1)
        THROW("Unsupported digest method %.*s", int(uri.size()), uri.data());
    int method = toMethod(uri.empty() ? Conf::instance()->digestUri() : uri);
    if(EVP_DigestInit(d.get(), EVP_get_digestbynid(method)) != 1)
        THROW_OPENSSLEXCEPTION("Failed to initialize %.*s digest calculator", int(uri.size()), uri.data());
}

vector<unsigned char> Digest::addDigestInfo(vector<unsigned char> digest, string_view uri)
{
    switch(toMethod(uri))
    {
    case NID_sha1: digest.insert(digest.cbegin(),
        {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14}); break;
    case NID_sha224: digest.insert(digest.cbegin(),
        {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c}); break;
    case NID_sha256: digest.insert(digest.cbegin(),
        {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}); break;
    case NID_sha384: digest.insert(digest.begin(),
        {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30}); break;
    case NID_sha512: digest.insert(digest.cbegin(),
        {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40}); break;
    default: break;
    }
    return digest;
}

vector<unsigned char> Digest::digestInfoDigest(const std::vector<unsigned char> &digest)
{
    const unsigned char *p = digest.data();
    SCOPE(X509_SIG, sig, d2i_X509_SIG(nullptr, &p, long(digest.size())));
    if(!sig)
        return {};
    const ASN1_OCTET_STRING *value {};
    X509_SIG_get0(sig.get(), nullptr, &value);
    return { value->data, std::next(value->data, value->length) };
}

string Digest::digestInfoUri(const std::vector<unsigned char> &digest)
{
    const unsigned char *p = digest.data();
    SCOPE(X509_SIG, sig, d2i_X509_SIG(nullptr, &p, long(digest.size())));
    if(!sig)
        return {};
    const X509_ALGOR *algor {};
    X509_SIG_get0(sig.get(), &algor, nullptr);
    return toUri(OBJ_obj2nid(algor->algorithm));
}

/**
 * return returns digest method URI.
 * @see Digest::toMethod(const std::string& uri)
 */
string Digest::uri() const
{
    return toUri(EVP_MD_CTX_type(d.get()));
}

bool Digest::isRsaPssUri(string_view uri)
{
    return
        uri == URI_RSA_PSS_SHA224 ||
        uri == URI_RSA_PSS_SHA256 ||
        uri == URI_RSA_PSS_SHA384 ||
        uri == URI_RSA_PSS_SHA512 ||
#ifndef LIBRESSL_VERSION_NUMBER
        uri == URI_RSA_PSS_SHA3_224 ||
        uri == URI_RSA_PSS_SHA3_256 ||
        uri == URI_RSA_PSS_SHA3_384 ||
        uri == URI_RSA_PSS_SHA3_512;
#else
        false;
#endif
}

bool Digest::isWeakDigest(string_view uri)
{
    return toMethod(uri) == NID_sha1;
}

/**
 * Converts digest method URI to OpenSSL method id (e.g. 'http://www.w3.org/2000/09/xmldsig#sha1' to NID_sha1,
 * see openssl/obj_mac.h)
 * For available method URIs see:
 * <li>
 *   <ul><b>W3C XML Encryption Syntax and Processing</b> (10 December 2005) http://www.w3.org/TR/xmlenc-core/</ul>
 *   <ul><b>RFC 4051</b> https://www.ietf.org/rfc/rfc4051.txt</ul>
 *   <ul><b>RFC 6931</b> https://www.ietf.org/rfc/rfc6931.txt</ul>
 * </li>
 *
 * @param uri digest method URI (e.g. 'http://www.w3.org/2000/09/xmldsig#sha1' for SHA1).
 * @return returns digest OpenSSL method id.
 * @throws Exception throws exception if digest method is not supported.
 */
int Digest::toMethod(string_view uri)
{
    if(uri == URI_SHA1 || uri == URI_RSA_SHA1 || uri == URI_ECDSA_SHA1) return NID_sha1;
    if(uri == URI_SHA224 || uri == URI_RSA_SHA224 || uri == URI_RSA_PSS_SHA224 || uri == URI_ECDSA_SHA224) return NID_sha224;
    if(uri == URI_SHA256 || uri == URI_RSA_SHA256 || uri == URI_RSA_PSS_SHA256 || uri == URI_ECDSA_SHA256) return NID_sha256;
    if(uri == URI_SHA384 || uri == URI_RSA_SHA384 || uri == URI_RSA_PSS_SHA384 || uri == URI_ECDSA_SHA384) return NID_sha384;
    if(uri == URI_SHA512 || uri == URI_RSA_SHA512 || uri == URI_RSA_PSS_SHA512 || uri == URI_ECDSA_SHA512) return NID_sha512;
#ifndef LIBRESSL_VERSION_NUMBER
    if(uri == URI_SHA3_224 || uri == URI_RSA_PSS_SHA3_224) return NID_sha3_224;
    if(uri == URI_SHA3_256 || uri == URI_RSA_PSS_SHA3_256) return NID_sha3_256;
    if(uri == URI_SHA3_384 || uri == URI_RSA_PSS_SHA3_384) return NID_sha3_384;
    if(uri == URI_SHA3_512 || uri == URI_RSA_PSS_SHA3_512) return NID_sha3_512;
#endif
    THROW("Digest method URI '%.*s' is not supported.", int(uri.size()), uri.data());
}

string Digest::toRsaUri(const string &uri)
{
    DEBUG("method %s", uri.c_str());
    if(uri == URI_SHA1) return URI_RSA_SHA1;
    if(uri == URI_SHA224) return URI_RSA_SHA224;
    if(uri == URI_SHA256) return URI_RSA_SHA256;
    if(uri == URI_SHA384) return URI_RSA_SHA384;
    if(uri == URI_SHA512) return URI_RSA_SHA512;
    if(uri == URI_RSA_SHA1 ||
        uri == URI_RSA_SHA224 ||
        uri == URI_RSA_SHA256 ||
        uri == URI_RSA_SHA384 ||
        uri == URI_RSA_SHA512)
        return uri;
    return toRsaPssUri(uri);
}

string Digest::toRsaPssUri(string uri)
{
    if(uri == URI_SHA224) return URI_RSA_PSS_SHA224;
    if(uri == URI_SHA256) return URI_RSA_PSS_SHA256;
    if(uri == URI_SHA384) return URI_RSA_PSS_SHA384;
    if(uri == URI_SHA512) return URI_RSA_PSS_SHA512;
#ifndef LIBRESSL_VERSION_NUMBER
    if(uri == URI_SHA3_224) return URI_RSA_PSS_SHA3_224;
    if(uri == URI_SHA3_256) return URI_RSA_PSS_SHA3_256;
    if(uri == URI_SHA3_384) return URI_RSA_PSS_SHA3_384;
    if(uri == URI_SHA3_512) return URI_RSA_PSS_SHA3_512;
#endif
    if(isRsaPssUri(uri))
        return uri;
    return {};
}

string Digest::toEcUri(const string &uri)
{
    if(uri == URI_SHA1) return URI_ECDSA_SHA1;
    if(uri == URI_SHA224) return URI_ECDSA_SHA224;
    if(uri == URI_SHA256) return URI_ECDSA_SHA256;
    if(uri == URI_SHA384) return URI_ECDSA_SHA384;
    if(uri == URI_SHA512) return URI_ECDSA_SHA512;
    if(uri == URI_ECDSA_SHA1 ||
        uri == URI_ECDSA_SHA224 ||
        uri == URI_ECDSA_SHA256 ||
        uri == URI_ECDSA_SHA384 ||
        uri == URI_ECDSA_SHA512)
        return uri;
    return {};
}

std::string Digest::toUri(int nid)
{
    switch(nid)
    {
    case NID_sha1: return URI_SHA1;
    case NID_sha224: return URI_SHA224;
    case NID_sha256: return URI_SHA256;
    case NID_sha384: return URI_SHA384;
    case NID_sha512: return URI_SHA512;
#ifndef LIBRESSL_VERSION_NUMBER
    case NID_sha3_224: return URI_SHA3_224;
    case NID_sha3_256: return URI_SHA3_256;
    case NID_sha3_384: return URI_SHA3_384;
    case NID_sha3_512: return URI_SHA3_512;
#endif
    default: return {};
    }
}

/**
 * Add data for digest calculation. After calling <code>result()</code> SHA context
 * is uninitialized and this method should not be called.
 *
 * @param data data to add for digest calculation.
 * @param length length of the data.
 * @throws Exception throws exception if update failed.
 * @see result()
 */
void Digest::update(const unsigned char *data, size_t length) const
{
    if(!data)
        THROW("Can not update digest value from NULL pointer.");
    if(EVP_DigestUpdate(d.get(), data, length) != 1)
        THROW_OPENSSLEXCEPTION("Failed to update %s digest value", uri().c_str());
}

/**
 * Add data for digest calculation. After calling <code>result()</code> SHA context
 * is uninitialized and this method should not be called.
 *
 * @param is stream to add for digest calculation.
 * @throws Exception throws exception if update failed.
 * @see result()
 */
void Digest::update(istream &is) const
{
    array<unsigned char, 10240> buf{};
    while(is)
    {
        is.read((char*)buf.data(), streamsize(buf.size()));
        if(is.gcount() > 0)
            update(buf.data(), size_t(is.gcount()));
    }
}

/**
 * Calculate message digest. SHA context will be invalid after this call.
 * For calculating an other digest you must create new Digest class.
 *
 * @return returns the calculated digest.
 * @throws Exception throws exception if update failed.
 */
vector<unsigned char> Digest::result() const
{
    unsigned int size = 0;
    vector<unsigned char> result(size_t(EVP_MD_CTX_size(d.get())), 0);
    if(EVP_DigestFinal_ex(d.get(), result.data(), &size) != 1)
        THROW_OPENSSLEXCEPTION("Failed to create %s digest", uri().c_str());
    return result;
}

vector<unsigned char> Digest::result(const vector<unsigned char> &data)
{
    update(data.data(), data.size());
    return result();
}
