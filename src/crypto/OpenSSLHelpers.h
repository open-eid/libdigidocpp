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

#include "Exception.h"
#include "log.h"

#include <memory>
#include <sstream>

#include <openssl/err.h>
#include <openssl/pkcs12.h>

#ifndef RSA_PSS_SALTLEN_DIGEST
#define RSA_PSS_SALTLEN_DIGEST -1
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#include <openssl/x509.h>

static EVP_PKEY *X509_get0_pubkey(X509 *x)
{
    if(!x)
        return nullptr;
    EVP_PKEY *key = X509_get_pubkey(x);
    EVP_PKEY_free(key);
    return key;
}

static void X509_SIG_get0(const X509_SIG *sig, const X509_ALGOR **palg, const ASN1_OCTET_STRING **pdigest)
{
    if(palg)
        *palg = sig->algor;
    if(pdigest)
        *pdigest = sig->digest;
}

static RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey)
{
    if(pkey->type == EVP_PKEY_RSA || pkey->type != NID_rsassaPss)
        return pkey->pkey.rsa;
    return nullptr;
}

static EC_KEY *EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey)
{
    if(pkey->type == EVP_PKEY_EC)
        return pkey->pkey.ec;
    return nullptr;
}

static void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
    if(pr) *pr = sig->r;
    if(ps) *ps = sig->s;
}

static int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    if(!r || !s) return 0;
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;
    return 1;
}
#endif

namespace digidoc
{

#define SCOPE2(TYPE, VAR, DATA, FREE) std::unique_ptr<TYPE,decltype(&FREE)> VAR(static_cast<TYPE*>(DATA), FREE)
#define SCOPE(TYPE, VAR, DATA) SCOPE2(TYPE, VAR, DATA, TYPE##_free)

template<class T, typename Func>
std::vector<unsigned char> i2d(T *obj, Func func)
{
    std::vector<unsigned char> result;
    if(!obj)
        return result;
    int size = func(obj, nullptr);
    if(size <= 0)
        return result;
    result.resize(size_t(size));
    unsigned char *p = result.data();
    if(func(obj, &p) <= 0)
        result.clear();
    return result;
}

/**
 * OpenSSL exception implementation. Thrown if the openssl returns error
 */
class OpenSSLException : public Exception
{
    public:
        OpenSSLException(const std::string &file, int line, const std::string &msg)
            : Exception(file, line, msg)
        {
            unsigned long error = 0;
            while((error = ERR_get_error()) != 0)
            {
                Exception e(ERR_lib_error_string(error), 0, ERR_error_string(error, nullptr));
                if(ERR_GET_LIB(error) == ERR_R_BIO_LIB &&
                    ERR_GET_FUNC(error) == BIO_F_BIO_LOOKUP_EX &&
                    ERR_GET_REASON(error) == ERR_R_SYS_LIB)
                    e.setCode(ExceptionCode::HostNotFound);
                addCause(e);
            }
        }
};

#define THROW_OPENSSLEXCEPTION(...) throw OpenSSLException(EXCEPTION_PARAMS(__VA_ARGS__))

class OpenSSL
{
public:
    static void parsePKCS12(const std::string &path, const std::string &pass, EVP_PKEY **key, X509 **cert)
    {
        SCOPE(BIO, bio, BIO_new_file(path.c_str(), "rb"));
        if(!bio)
            THROW_OPENSSLEXCEPTION("Failed to open PKCS12 certificate: %s.", path.c_str());
        SCOPE(PKCS12, p12, d2i_PKCS12_bio(bio.get(), nullptr));
        if(!p12)
            THROW_OPENSSLEXCEPTION("Failed to read PKCS12 certificate: %s.", path.c_str());
        if(!PKCS12_parse(p12.get(), pass.c_str(), key, cert, nullptr))
            THROW_OPENSSLEXCEPTION("Failed to parse PKCS12 certificate.");
        // Hack: clear PKCS12_parse error ERROR: 185073780 - error:0B080074:x509 certificate routines:X509_check_private_key:key values mismatch
        OpenSSLException(EXCEPTION_PARAMS("ignore"));
    }
};

}
