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

#include "PKCS12Signer.h"

#include "crypto/Digest.h"
#include "crypto/OpenSSLHelpers.h"
#include "crypto/X509Cert.h"
#include "util/log.h"

#include <algorithm>

using namespace digidoc;
using namespace std;

class PKCS12Signer::Private
{
public:
    X509 *cert {};
    EVP_PKEY *key {};
};

/**
 * @class digidoc::PKCS12Signer
 * @brief Implements <code>Signer</code> interface for PKCS#12 files.
 */


/**
 * Initializes the PKCS12 signer with PKCS#12 file and password.
 *
 * @param path PKCS#12 file path
 * @param pass PKCS#12 file password
 * @throws Exception throws exception if the file is not found or wrong password
 */
PKCS12Signer::PKCS12Signer(const string &path, const string &pass)
    : d(make_unique<Private>())
{
    OpenSSL::parsePKCS12(path, pass, &d->key, &d->cert);
}

PKCS12Signer::~PKCS12Signer()
{
    X509_free(d->cert);
    EVP_PKEY_free(d->key);
}

X509Cert PKCS12Signer::cert() const
{
    return X509Cert(d->cert);
}

vector<unsigned char> PKCS12Signer::sign(const string &method, const vector<unsigned char> &digest) const
{
    DEBUG("PKCS12Signer::sign(method = %s, digest = %lu)", method.c_str(), (unsigned long)digest.size());

    int result = 0;
    vector<unsigned char> signature;
    size_t size = 0;
    SCOPE(EVP_PKEY_CTX, ctx, EVP_PKEY_CTX_new(d->key, nullptr));
    if(!ctx || EVP_PKEY_sign_init(ctx.get()) <= 0)
        THROW_OPENSSLEXCEPTION("Failed to sign the digest");
    switch(EVP_PKEY_base_id(d->key))
    {
    case EVP_PKEY_RSA:
    {
        if(Digest::isRsaPssUri(method)) {
            if(EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PSS_PADDING) <= 0 ||
                EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx.get(), RSA_PSS_SALTLEN_DIGEST) <= 0)
                break;
        } else if(EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING) <= 0)
            break;
        if(EVP_PKEY_CTX_set_signature_md(ctx.get(), EVP_get_digestbynid(Digest::toMethod(method))) <= 0 ||
            EVP_PKEY_sign(ctx.get(), nullptr, &size, digest.data(), digest.size()) <= 0)
            break;
        signature.resize(size);
        result = EVP_PKEY_sign(ctx.get(), signature.data(), &size, digest.data(), digest.size());
        break;
    }
#ifndef OPENSSL_NO_ECDSA
    case EVP_PKEY_EC:
    {
        if(EVP_PKEY_sign(ctx.get(), nullptr, &size, digest.data(), digest.size()) <= 0)
            break;
        vector<unsigned char> asn1(size);
        result = EVP_PKEY_sign(ctx.get(), asn1.data(), &size, digest.data(), digest.size());
        if(result <= 0)
            break;
        const unsigned char *p = asn1.data();
        SCOPE(ECDSA_SIG, sig, d2i_ECDSA_SIG(nullptr, &p, long(asn1.size())));
        const BIGNUM *r = nullptr, *s = nullptr;
        ECDSA_SIG_get0(sig.get(), &r, &s);
        size_t r_len = size_t(BN_num_bytes(r));
        size_t s_len = size_t(BN_num_bytes(s));
        size_t keyLen = max(r_len, s_len);
        signature.resize(keyLen * 2);
        if(BN_bn2bin(r, &signature[keyLen - r_len]) <= 0)
            THROW("Error copying signature 'r' value to buffer");
        if(BN_bn2bin(s, &signature[keyLen*2 - s_len]) <= 0)
            THROW("Error copying signature 's' value to buffer");
        break;
    }
#endif
    default: THROW("Unsupported private key");
    }
    if(result != 1)
        THROW_OPENSSLEXCEPTION("Failed to sign the digest");
    return signature;
}
