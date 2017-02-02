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
class X509CertStorePrivate: public vector<X509Cert> {
public:
    void update()
    {
        vector<X509Cert> list = TSL::parse(CONF(TSLTimeOut));
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

    string path = Conf::instance()->certsPath();
    if(path.empty())
        return;

    if(!util::File::directoryExists(path))
    {
        WARN("Directory %s does not exists, can not load cert store.", path.c_str());
        return;
    }

    for(const std::string &file: util::File::listFiles(path))
    {
        string ext = file.substr(file.size() - 3);
        transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        if(ext != "pem" && ext != "crt")
            continue;
        try {
            d->push_back(X509Cert(file));
        } catch(const Exception &e) {
            WARN("Failed to parse cert '%s': %s", file.c_str(),
                 e.causes().empty() ? e.msg().c_str() : e.causes().front().msg().c_str());
        }
    }
    INFO("Loaded %d certificates into certificate store.", certs().size());
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
    return *d;
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
    for(const X509Cert &i: *d)
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
    return X509Cert();
}

/**
 * Check if X509Cert is signed by trusted issuer
 * @return 0 or openssl error_code. Get human readable cause with X509_verify_cert_error_string(code)
 * @throw IOException if error
 */
bool X509CertStore::verify(const X509Cert &cert, bool ca, time_t *t) const
{
    activate(cert.issuerName("C"));

    SCOPE(X509_STORE, store, X509_STORE_new());
    for(const X509Cert &i: *d)
        X509_STORE_add_cert(store.get(), i.handle());
    OpenSSLException(); // Clear Errors

    SCOPE(X509_STORE_CTX, csc, X509_STORE_CTX_new());
    if (!csc)
        THROW_OPENSSLEXCEPTION("Failed to create X509_STORE_CTX");

    if(!X509_STORE_CTX_init(csc.get(), store.get(), cert.handle(), 0))
        THROW_OPENSSLEXCEPTION("Failed to init X509_STORE_CTX");

#if 0
    csc.get()->check_issued = [](X509_STORE_CTX *ctx, X509 *x, X509 *issuer) -> int {
        SCOPE(AUTHORITY_KEYID, akid, (AUTHORITY_KEYID*)X509_get_ext_d2i(x, NID_authority_key_identifier, 0, 0));
        SCOPE(ASN1_OCTET_STRING, skid, (ASN1_OCTET_STRING*)X509_get_ext_d2i(issuer, NID_subject_key_identifier, 0, 0));
        if(akid.get() && skid.get() && ASN1_OCTET_STRING_cmp(akid->keyid, skid.get()) != 0)
            return X509_V_ERR_AKID_SKID_MISMATCH;

        int ret = X509_check_issued(issuer, x);
        if (ret == X509_V_OK)
            return 1;
        /* If we haven't asked for issuer errors don't set ctx */
        if (!(ctx->param->flags & X509_V_FLAG_CB_ISSUER_CHECK))
            return 0;

        ctx->error = ret;
        ctx->current_cert = x;
        ctx->current_issuer = issuer;
        return ctx->verify_cb(0, ctx);
    };

    csc.get()->get_issuer = [](X509 **issuer, X509_STORE_CTX *ctx, X509 *x) -> int {
        SCOPE(AUTHORITY_KEYID, akid, (AUTHORITY_KEYID*)X509_get_ext_d2i(x, NID_authority_key_identifier, 0, 0));
        if(!akid || !akid->keyid)
            return 0;

        STACK_OF(X509) *sk = (STACK_OF(X509)*)ctx->other_ctx;
        for(int i = 0; i < sk_X509_num(sk); ++i)
        {
            X509 *x509 = sk_X509_value(sk, i);
            SCOPE(ASN1_OCTET_STRING, skid, (ASN1_OCTET_STRING*)X509_get_ext_d2i(x509, NID_subject_key_identifier, 0, 0));
            if(skid.get() && ASN1_OCTET_STRING_cmp(akid->keyid, skid.get()) == 0)
            {
                *issuer = x509;
                CRYPTO_add(&(*issuer)->references,1,CRYPTO_LOCK_X509);
                return 1;
            }
        }
        return 0;
    };
#endif

    X509_STORE_CTX_set_verify_cb(csc.get(), [](int ok, X509_STORE_CTX *ctx) -> int {
        switch(X509_STORE_CTX_get_error(ctx))
        {
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        case X509_V_ERR_CERT_UNTRUSTED:
        {
            if(find(instance()->d->begin(), instance()->d->end(), X509Cert(ctx->current_cert)) != instance()->d->end())
                return 1;
            return ok;
        }
        default: return ok;
        }
    });

    if(t)
    {
        X509_STORE_CTX_set_time(csc.get(), 0, *t);
        X509_STORE_CTX_set_flags(csc.get(), X509_V_FLAG_USE_CHECK_TIME);
    }

    if(X509_verify_cert(csc.get()) > 0)
    {
        if(!ca)
            return true;

        if(cert.issuerName("CN") == "EID-SK 2016")
        {
            vector<string> policy = cert.certificatePolicies();
            vector<string> qcstatement = cert.qcStatements();
            bool policyIdSupportedByQSCD =
                find(policy.cbegin(), policy.cend(), X509Cert::QCP_PUBLIC_WITH_SSCD) != policy.cend() ||
                find(policy.cbegin(), policy.cend(), X509Cert::QCP_LEGAL_QSCD) != policy.cend() ||
                find(policy.cbegin(), policy.cend(), X509Cert::QCP_NATURAL_QSCD) != policy.cend();
            bool qcStatementSupportedByQSCD =
                find(qcstatement.cbegin(), qcstatement.cend(), X509Cert::QC_SSCD) != qcstatement.cend();

            if(!(policyIdSupportedByQSCD || qcStatementSupportedByQSCD))
            {
                Exception e(EXCEPTION_PARAMS("Signing certificate does not meet Qualification requirements"));
                e.setCode(Exception::CertificateIssuerMissing);
                throw e;
            }
        }

        return true;
    }

    int err = X509_STORE_CTX_get_error(csc.get());
    Exception e(__FILE__, __LINE__, X509_verify_cert_error_string(err), OpenSSLException());
    switch(err)
    {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: e.setCode(Exception::CertificateIssuerMissing);
    default: throw e;
    }

    return false;
}
