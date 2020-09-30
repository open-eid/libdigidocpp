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
#include "log.h"

using namespace digidoc;
using namespace std;

class PKCS12Signer::Private
{
public:
    X509 *cert = nullptr;
    EVP_PKEY *key = nullptr;
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
 : d(new Private)
{
    OpenSSL::parsePKCS12(path, pass, &d->key, &d->cert);
}

PKCS12Signer::~PKCS12Signer()
{
    X509_free(d->cert);
    EVP_PKEY_free(d->key);
    delete d;
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
    switch(EVP_PKEY_base_id(d->key))
    {
    case EVP_PKEY_RSA:
    {
        RSA *rsa = EVP_PKEY_get0_RSA(d->key);
        signature.resize(size_t(RSA_size(rsa)));
        int nid = Digest::toMethod(method);
        if(Digest::isRsaPssUri(method)) {
            vector<unsigned char> em(signature.size());
            if (!RSA_padding_add_PKCS1_PSS_mgf1(rsa, em.data(), digest.data(), EVP_get_digestbynid(nid), nullptr, RSA_PSS_SALTLEN_DIGEST))
                break;
            if(RSA_private_encrypt(RSA_size(rsa), em.data(), signature.data(), rsa, RSA_NO_PADDING) == RSA_size(rsa))
                result = 1;
        } else {
            unsigned int size = (unsigned int)signature.size();
            result = RSA_sign(nid, digest.data(), (unsigned int)digest.size(), signature.data(), &size, rsa);
        }
        break;
    }
#ifndef OPENSSL_NO_ECDSA
    case EVP_PKEY_EC:
    {
        EC_KEY *ec = EVP_PKEY_get0_EC_KEY(d->key);
        SCOPE(ECDSA_SIG, sig, ECDSA_do_sign(digest.data(), int(digest.size()), ec));
        if(!sig)
             break;

        size_t keyLen = 0;
        if(const EC_GROUP *group = EC_KEY_get0_group(ec))
        {
            BIGNUM *order = BN_new();
            if (EC_GROUP_get_order(group, order, nullptr))
                keyLen = size_t(BN_num_bytes(order));
            BN_clear_free(order);
        }
        if(keyLen == 0)
             THROW("Error caclulating signature size");
        signature.resize(keyLen * 2);

        const BIGNUM *r = nullptr, *s = nullptr;
        ECDSA_SIG_get0(sig.get(), &r, &s);
        if(BN_bn2bin(r, &signature[keyLen - size_t(BN_num_bytes(r))]) <= 0)
            THROW("Error copying signature 'r' value to buffer");
        if(BN_bn2bin(s, &signature[keyLen*2 - size_t(BN_num_bytes(s))]) <= 0)
            THROW("Error copying signature 's' value to buffer");

        result = 1;
        break;
    }
#endif
    default: THROW("Unsupported private key");
    }
    if(result != 1)
        THROW_OPENSSLEXCEPTION("Failed to sign the digest");
    return signature;
}
