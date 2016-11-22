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

#include "X509CertStore.h"

#include "Conf.h"
#include "log.h"
#include "crypto/OpenSSLHelpers.h"
#include "crypto/TSL.h"
#include "util/DateTime.h"
#include "util/File.h"

#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <iomanip>

using namespace digidoc;
using namespace std;

namespace digidoc
{
class X509CertStorePrivate: public vector<TSL::Service> {
public:
    void update()
    {
        vector<TSL::Service> list = TSL::parse(CONF(TSLTimeOut));
        swap(list);
        INFO("Loaded %d certificates into TSL certificate store.", size());
    }
};
}

/**
 * X509CertStore constructor.
 */
X509CertStore::X509CertStore()
    : d(new X509CertStorePrivate)
{
    SSL_load_error_strings();
    SSL_library_init();
    OPENSSL_config(0);
    d->update();
}

/**
 * Release all certificates.
 */
X509CertStore::~X509CertStore()
{
    delete d;
}

void X509CertStore::activate(const string &territory) const
{
    if(TSL::activate(territory))
        d->update();
}

/**
 * @return returns the X.509 certificate store implementation.
 */
X509CertStore* X509CertStore::instance()
{
    static X509CertStore INSTANCE;
    return &INSTANCE;
}


/**
 * Return STACK_OF(X509) containing all certs loaded from directory
 * @return STACK_OF(X509) all certs in store.
 * throws IOException
 */
vector<X509Cert> X509CertStore::certs() const
{
    vector<X509Cert> certs;
    for(const TSL::Service &s: *d)
        certs.insert(certs.end(), s.certs.cbegin(), s.certs.cend());
    return certs;
}

/**
 * Searches certificate by subject and returns a copy of it if found.
 * If not found returns <code>NULL</code>.
 * NB! The returned certificate must be freed with OpenSSL function X509_free(X509* cert).
 *
 * @param subject certificate subject.
 * @return returns copy of found certificate or <code>NULL</code> if certificate was not found.
 * @throws IOException exception is thrown if copying certificate failed.
 */
X509Cert X509CertStore::findIssuer(const X509Cert &cert) const
{
    activate(cert.issuerName("C"));
    SCOPE(AUTHORITY_KEYID, akid, (AUTHORITY_KEYID*)X509_get_ext_d2i(cert.handle(), NID_authority_key_identifier, 0, 0));
    for(const TSL::Service &s: *d)
    {
        for(const X509Cert &i: s.certs)
        {
            if(!akid || !akid->keyid)
            {
                if(X509_NAME_cmp(X509_get_subject_name(i.handle()), X509_get_issuer_name(cert.handle())))
                    return i;
            }
            else
            {
                SCOPE(ASN1_OCTET_STRING, skid, (ASN1_OCTET_STRING*)X509_get_ext_d2i(i.handle(), NID_subject_key_identifier, 0, 0));
                if(skid.get() && ASN1_OCTET_STRING_cmp(akid->keyid, skid.get()) == 0)
                    return i;
            }
        }
    }
    return X509Cert();
}

X509_STORE* X509CertStore::createStore(time_t *t)
{
    SCOPE(X509_STORE, store, X509_STORE_new());
    if (!store)
        THROW_OPENSSLEXCEPTION("Failed to create X509_STORE_CTX");

    X509_STORE_set_verify_cb(store.get(), [](int ok, X509_STORE_CTX *ctx) -> int {
        switch(X509_STORE_CTX_get_error(ctx))
        {
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        case X509_V_ERR_CERT_UNTRUSTED:
        {
            SCOPE(AUTHORITY_KEYID, akid, (AUTHORITY_KEYID*)X509_get_ext_d2i(ctx->current_cert, NID_authority_key_identifier, 0, 0));
            DEBUG("Find %s", X509Cert(ctx->current_cert).subjectName("CN").c_str());
            for(const TSL::Service &s: *instance()->d)
            {
                auto certFound = find_if(s.certs.cbegin(), s.certs.cend(), [&](const X509Cert &issuer){
                    if(X509_cmp(ctx->current_cert, issuer.handle()) == 0)
                        return true;
                    if(!akid || !akid->keyid)
                    {
                        if(X509_NAME_cmp(X509_get_subject_name(issuer.handle()), X509_get_issuer_name(ctx->current_cert)) != 0)
                            return false;
                    }
                    else
                    {
                        SCOPE(ASN1_OCTET_STRING, skid, (ASN1_OCTET_STRING*)X509_get_ext_d2i(issuer.handle(), NID_subject_key_identifier, 0, 0));
                        if(!skid.get() || ASN1_OCTET_STRING_cmp(akid->keyid, skid.get()) != 0)
                            return false;
                    }
                    SCOPE(EVP_PKEY, pub, X509_get_pubkey(issuer.handle()));
                    if(X509_verify(ctx->current_cert, pub.get()) == 1)
                        return true;
                    OpenSSLException(); //Clear errors
                    return false;
                });
                if(certFound == s.certs.cend())
                    continue;
                if(!(ctx->param->flags & X509_V_FLAG_USE_CHECK_TIME) || s.validity.empty())
                    return 1;
                for(const TSL::Validity &v: s.validity)
                {
                    if(ctx->param->check_time >= v.start && (v.end == 0 || ctx->param->check_time <= v.end))
                        return 1;
                }
            }
            return ok;
        }
        default: return ok;
        }
    });

    if(t)
    {
        X509_VERIFY_PARAM_set_time(store->param, *t);
        X509_STORE_set_flags(store.get(), X509_V_FLAG_USE_CHECK_TIME);
    }
    return store.release();
}

/**
 * Check if X509Cert is signed by trusted issuer
 * @throw Exception if error
 */
bool X509CertStore::verify(const X509Cert &cert, time_t *t) const
{
    activate(cert.issuerName("C"));
    SCOPE(X509_STORE, store, createStore(t));
    SCOPE(X509_STORE_CTX, csc, X509_STORE_CTX_new());
    if(!X509_STORE_CTX_init(csc.get(), store.get(), cert.handle(), nullptr))
        THROW_OPENSSLEXCEPTION("Failed to init X509_STORE_CTX");
    if(X509_verify_cert(csc.get()) > 0)
        return true;
    int err = X509_STORE_CTX_get_error(csc.get());
    Exception e(__FILE__, __LINE__, X509_verify_cert_error_string(err), OpenSSLException());
    switch(err)
    {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        e.setCode(Exception::CertificateIssuerMissing);
        throw e;
    default: throw e;
    }
}
