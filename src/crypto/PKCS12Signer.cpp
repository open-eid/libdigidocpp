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
struct PKCS12SignerPrivate
{
    PKCS12SignerPrivate(): cert(0), key(0) {}
    X509 *cert;
    EVP_PKEY *key;
};
}
using namespace digidoc;
using namespace std;

/**
 * Initializes the RSA signer with X.509 certificate and private key pair.
 *
 * @param cert X.509 certificate of the private key.
 * @param privateKey private key, should match the X.509 certificate.
 * @throws SignException throws exception if the certificate or the private key
 *         is NULL.
 */
PKCS12Signer::PKCS12Signer(const string &path, const string &pass)
 : d(new PKCS12SignerPrivate)
{
    BIO *bio = BIO_new_file(path.c_str(), "rb");
    if(!bio)
        THROW_CAUSE(OpenSSLException(), "Failed to open PKCS12 certificate: %s.", path.c_str());
    SCOPE(PKCS12, p12, d2i_PKCS12_bio(bio, 0));
    BIO_free(bio);
    if(!p12)
        THROW_CAUSE(OpenSSLException(), "Failed to read PKCS12 certificate: %s.", path.c_str());

    if(!PKCS12_parse(p12.get(), pass.c_str(), &d->key, &d->cert, 0))
        THROW_CAUSE(OpenSSLException(), "Failed to parse PKCS12 certificate.");
    else // Hack: clear PKCS12_parse error ERROR: 185073780 - error:0B080074:x509 certificate routines:X509_check_private_key:key values mismatch
        OpenSSLException();
}

/**
 *
 */
PKCS12Signer::~PKCS12Signer()
{
    X509_free(d->cert);
    EVP_PKEY_free(d->key);
    delete d;
}

/**
 * Returns the X.509 certificate used for signing.
 *
 * @return returns certificate used for signing.
 * @throws throws never thrown.
 */
X509Cert PKCS12Signer::cert() const
{
    return X509Cert(d->cert);
}

/**
 * Signs the provided digest using the private key that matches the X.509 certificate.
 *
 * @param digest digest, which is being signed.
 * @param signature memory for the signature that is created. Struct parameter <code>length</code>
 *        is set to the actual signature length.
 * @throws SignException throws exception if the signing operation failed or not enough memory
 *         allocated for the signature.
 */
void PKCS12Signer::sign(const string &method, const vector<unsigned char> &digest, vector<unsigned char> &signature)
{
    DEBUG("PKCS12Signer::sign(method = %s, digest = %d)", method.c_str(), digest.size());

    int nid = NID_sha1;
    if ( method == URI_RSA_SHA224 ) nid = NID_sha224;
    if ( method == URI_RSA_SHA256 ) nid = NID_sha256;
    if ( method == URI_RSA_SHA384 ) nid = NID_sha384;
    if ( method == URI_RSA_SHA512 ) nid = NID_sha512;

    int result = 0;
    switch(EVP_PKEY_type(d->key->type))
    {
    case EVP_PKEY_RSA:
    {
        SCOPE(RSA, rsa, EVP_PKEY_get1_RSA(d->key));
        signature.resize(RSA_size(rsa.get()));
        unsigned int size = (unsigned int)signature.size();
        result = RSA_sign(nid, &digest[0], (unsigned int)digest.size(), &signature[0], &size, rsa.get());
        break;
    }
#ifndef OPENSSL_NO_ECDSA
    case EVP_PKEY_EC:
    {
        SCOPE(EC_KEY, ec, EVP_PKEY_get1_EC_KEY(d->key));
        SCOPE(ECDSA_SIG, sig, ECDSA_do_sign(&digest[0], (unsigned int)digest.size(), ec.get()));
        if(!sig)
            break;
        signature.resize(BN_num_bytes(sig->r) + BN_num_bytes(sig->s));
        unsigned int size = BN_bn2bin(sig->r, &signature[0]);
        BN_bn2bin(sig->s, &signature[size]);
        result = 1;
        break;
    }
#endif
    default: THROW("Unsupported private key");
    }
    if(result != 1)
        THROW_CAUSE(OpenSSLException(), "Failed to sign the digest");
}
