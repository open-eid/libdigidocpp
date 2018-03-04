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

#include "log.h"
#include "crypto/Digest.h"
#include "crypto/OpenSSLHelpers.h"
#include "crypto/X509Cert.h"

#include <openssl/pkcs12.h>
#include <openssl/x509.h>

namespace digidoc
{
class PKCS12SignerPrivate
{
public:
    X509 *cert = nullptr;
    EVP_PKEY *key = nullptr;
};
}
using namespace digidoc;
using namespace std;

#if OPENSSL_VERSION_NUMBER < 0x10010000L
static void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
    if(pr) *pr = sig->r;
    if(ps) *ps = sig->s;
}
#endif

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
 : d(new PKCS12SignerPrivate)
{
    SCOPE(BIO, bio, BIO_new_file(path.c_str(), "rb"));
    if(!bio)
        THROW_CAUSE(OpenSSLException(), "Failed to open PKCS12 certificate: %s.", path.c_str());
    SCOPE(PKCS12, p12, d2i_PKCS12_bio(bio.get(), 0));
    if(!p12)
        THROW_CAUSE(OpenSSLException(), "Failed to read PKCS12 certificate: %s.", path.c_str());

    if(!PKCS12_parse(p12.get(), pass.c_str(), &d->key, &d->cert, 0))
        THROW_CAUSE(OpenSSLException(), "Failed to parse PKCS12 certificate.");
    else // Hack: clear PKCS12_parse error ERROR: 185073780 - error:0B080074:x509 certificate routines:X509_check_private_key:key values mismatch
        OpenSSLException();
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
    DEBUG("PKCS12Signer::sign(method = %s, digest = %d)", method.c_str(), digest.size());

    int result = 0;
    vector<unsigned char> signature;
    switch(EVP_PKEY_base_id(d->key))
    {
    case EVP_PKEY_RSA:
    {
        SCOPE(RSA, rsa, EVP_PKEY_get1_RSA(d->key));
        signature.resize(size_t(RSA_size(rsa.get())));
        int nid = Digest::toMethod(method);
        unsigned int size = (unsigned int)signature.size();
        result = RSA_sign(nid, &digest[0], (unsigned int)digest.size(), signature.data(), &size, rsa.get());
        break;
    }
#ifndef OPENSSL_NO_ECDSA
    case EVP_PKEY_EC:
    {
        SCOPE(EC_KEY, ec, EVP_PKEY_get1_EC_KEY(d->key));
        SCOPE(ECDSA_SIG, sig, ECDSA_do_sign(&digest[0], (unsigned int)digest.size(), ec.get()));
        if(!sig)
             break;

        unsigned int keyLen = 0;
        if(const EC_GROUP *group = EC_KEY_get0_group(ec.get()))
        {
            BIGNUM *order = BN_new();
            if (EC_GROUP_get_order(group, order, nullptr))
                keyLen = BN_num_bytes(order);
            BN_clear_free(order);
        }
        if(keyLen == 0)
             THROW("Error caclulating signature size");
        signature.resize(keyLen * 2);

        const BIGNUM *r = nullptr, *s = nullptr;
        ECDSA_SIG_get0(sig.get(), &r, &s);
        if(BN_bn2bin(r, &signature[keyLen - BN_num_bytes(r)]) <= 0)
            THROW("Error copying signature 'r' value to buffer");
        if(BN_bn2bin(s, &signature[keyLen*2 - BN_num_bytes(s)]) <= 0)
            THROW("Error copying signature 's' value to buffer");

        result = 1;
        break;
    }
#endif
    default: THROW("Unsupported private key");
    }
    if(result != 1)
        THROW_CAUSE(OpenSSLException(), "Failed to sign the digest");
    return signature;
}
