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

#if OPENSSL_VERSION_NUMBER < 0x10010000L
static X509 *X509_STORE_CTX_get0_cert(X509_STORE_CTX *ctx)
{
    return ctx->cert;
}

static X509_VERIFY_PARAM *X509_STORE_get0_param(X509_STORE *ctx)
{
    return ctx->param;
}

static time_t X509_VERIFY_PARAM_get_time(const X509_VERIFY_PARAM *param)
{
    return param->check_time;
}

static const ASN1_TIME *X509_get0_notBefore(const X509 *x)
{
    return x->cert_info->validity->notBefore;
}
#endif

const set<string> X509CertStore::CA = {
    "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
};

const set<string> X509CertStore::TSA = {
    "http://uri.etsi.org/TrstSvc/Svctype/TSA",
    "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST",
    "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-QC",
    "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-AdESQCandQES",
};

const set<string> X509CertStore::OCSP = {
    "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
    "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP",
    "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC",
};

class X509CertStore::Private: public vector<TSL::Service> {
public:
    void update()
    {
        vector<TSL::Service> list = TSL::parse(CONF(TSLTimeOut));
        swap(list);
        INFO("Loaded %d certificates into TSL certificate store.", size());
    }
};

/**
 * X509CertStore constructor.
 */
X509CertStore::X509CertStore()
    : d(new Private)
{
    SSL_load_error_strings();
    SSL_library_init();
#if OPENSSL_VERSION_NUMBER < 0x10010000L
    OPENSSL_config(nullptr);
#endif
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
vector<X509Cert> X509CertStore::certs(const set<string> &type) const
{
    vector<X509Cert> certs;
    for(const TSL::Service &s: *d)
    {
        if(type.find(s.type) != type.cend())
            certs.insert(certs.end(), s.certs.cbegin(), s.certs.cend());
    }
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
X509Cert X509CertStore::findIssuer(const X509Cert &cert, const set<string> &type) const
{
    activate(cert.issuerName("C"));
    SCOPE(AUTHORITY_KEYID, akid, X509_get_ext_d2i(cert.handle(), NID_authority_key_identifier, nullptr, nullptr));
    for(const TSL::Service &s: *d)
    {
        if(type.find(s.type) == type.cend())
            continue;
        for(const X509Cert &i: s.certs)
        {
            if(!akid || !akid->keyid)
            {
                if(X509_NAME_cmp(X509_get_subject_name(i.handle()), X509_get_issuer_name(cert.handle())))
                    return i;
            }
            else
            {
                SCOPE(ASN1_OCTET_STRING, skid, X509_get_ext_d2i(i.handle(), NID_subject_key_identifier, nullptr, nullptr));
                if(skid.get() && ASN1_OCTET_STRING_cmp(akid->keyid, skid.get()) == 0)
                    return i;
            }
        }
    }
    return X509Cert();
}

X509_STORE* X509CertStore::createStore(const set<string> &type, const time_t *t)
{
    SCOPE(X509_STORE, store, X509_STORE_new());
    if (!store)
        THROW_OPENSSLEXCEPTION("Failed to create X509_STORE_CTX");

    if(type == CA)
        X509_STORE_set_verify_cb(store.get(), [](int ok, X509_STORE_CTX *ctx) -> int { return validate(ok, ctx, CA); });
    else if(type == OCSP)
        X509_STORE_set_verify_cb(store.get(), [](int ok, X509_STORE_CTX *ctx) -> int { return validate(ok, ctx, OCSP); });
    else if(type == TSA)
        X509_STORE_set_verify_cb(store.get(), [](int ok, X509_STORE_CTX *ctx) -> int { return validate(ok, ctx, TSA); });

    if(t)
    {
        X509_VERIFY_PARAM_set_time(X509_STORE_get0_param(store.get()), *t);
        X509_STORE_set_flags(store.get(), X509_V_FLAG_USE_CHECK_TIME);
    }
    return store.release();
}

int X509CertStore::validate(int ok, X509_STORE_CTX *ctx, const set<string> &type)
{
    switch(X509_STORE_CTX_get_error(ctx))
    {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    case X509_V_ERR_CERT_UNTRUSTED:
    {
        X509 *x509 = X509_STORE_CTX_get0_cert(ctx);
        SCOPE(AUTHORITY_KEYID, akid, X509_get_ext_d2i(x509, NID_authority_key_identifier, nullptr, nullptr));
        for(const TSL::Service &s: *instance()->d)
        {
            if(type.find(s.type) == type.cend())
                continue;
            auto certFound = find_if(s.certs.cbegin(), s.certs.cend(), [&](const X509Cert &issuer){
                if(X509_cmp(x509, issuer.handle()) == 0)
                    return true;
                if(!akid || !akid->keyid)
                {
                    if(X509_NAME_cmp(X509_get_subject_name(issuer.handle()), X509_get_issuer_name(x509)) != 0)
                        return false;
                }
                else
                {
                    SCOPE(ASN1_OCTET_STRING, skid, X509_get_ext_d2i(issuer.handle(), NID_subject_key_identifier, nullptr, nullptr));
                    if(!skid.get() || ASN1_OCTET_STRING_cmp(akid->keyid, skid.get()) != 0)
                        return false;
                }
                SCOPE(EVP_PKEY, pub, X509_get_pubkey(issuer.handle()));
                if(X509_verify(x509, pub.get()) == 1)
                    return true;
                OpenSSLException(); //Clear errors
                return false;
            });
            if(certFound == s.certs.cend())
                continue;
            X509_STORE_CTX_set_ex_data(ctx, 0, const_cast<TSL::Validity*>(&s.validity[0]));
            X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx);
            if(!(X509_VERIFY_PARAM_get_flags(param) & X509_V_FLAG_USE_CHECK_TIME) || s.validity.empty())
                return 1;
            for(const TSL::Validity &v: s.validity)
            {
                if(X509_VERIFY_PARAM_get_time(param) >= v.start && (v.end == 0 || X509_VERIFY_PARAM_get_time(param) <= v.end))
                {
                    X509_STORE_CTX_set_ex_data(ctx, 0, const_cast<TSL::Validity*>(&v));
                    return 1;
                }
            }
        }
        return ok;
    }
    default: return ok;
    }
}

/**
 * Check if X509Cert is signed by trusted issuer
 * @throw Exception if error
 */
bool X509CertStore::verify(const X509Cert &cert, bool noqscd) const
{
    activate(cert.issuerName("C"));
    const ASN1_TIME *asn1time = X509_get0_notBefore(cert.handle());
    time_t time = util::date::ASN1TimeToTime_t(string((const char*)asn1time->data, size_t(asn1time->length)), asn1time->type == V_ASN1_GENERALIZEDTIME);
    SCOPE(X509_STORE, store, createStore(X509CertStore::CA, &time));
    SCOPE(X509_STORE_CTX, csc, X509_STORE_CTX_new());
    if(!X509_STORE_CTX_init(csc.get(), store.get(), cert.handle(), nullptr))
        THROW_OPENSSLEXCEPTION("Failed to init X509_STORE_CTX");
    if(X509_verify_cert(csc.get()) > 0)
    {
        if(noqscd)
            return true;

        const TSL::Validity *v = static_cast<const TSL::Validity*>(X509_STORE_CTX_get_ex_data(csc.get(), 0));
        const vector<string> policies = cert.certificatePolicies();
        const vector<string> qcstatement = cert.qcStatements();
        const vector<X509Cert::KeyUsage> keyUsage = cert.keyUsage();

        bool isQCCompliant = find(qcstatement.cbegin(), qcstatement.cend(), X509Cert::QC_COMPLIANT) != qcstatement.cend();
        bool isQSCD =
            find(policies.cbegin(), policies.cend(), X509Cert::QCP_PUBLIC_WITH_SSCD) != policies.cend() ||
            find(policies.cbegin(), policies.cend(), X509Cert::QCP_LEGAL_QSCD) != policies.cend() ||
            find(policies.cbegin(), policies.cend(), X509Cert::QCP_NATURAL_QSCD) != policies.cend() ||
            find(qcstatement.cbegin(), qcstatement.cend(), X509Cert::QC_SSCD) != qcstatement.cend();

        auto matchPolicySet = [&](const vector<string> &policySet){
            return all_of(policySet.cbegin(), policySet.cend(), [&](const string &policy){
                return find(policies.cbegin(), policies.cend(), policy) != policies.cend();
            });
        };
        auto matchKeyUsageSet = [&](const map<X509Cert::KeyUsage,bool> &keyUsageSet){
            return all_of(keyUsageSet.cbegin(), keyUsageSet.cend(), [&](pair<X509Cert::KeyUsage,bool> keyUsageBit){
                return (find(keyUsage.cbegin(), keyUsage.cend(), keyUsageBit.first) != keyUsage.cend()) == keyUsageBit.second;
            });
        };

        for(const TSL::Qualifier &q: v->qualifiers)
        {
            if(q.assert_ == "all")
            {
                if(!(all_of(q.policySet.cbegin(), q.policySet.cend(), matchPolicySet) &&
                     all_of(q.keyUsage.cbegin(), q.keyUsage.cend(), matchKeyUsageSet)))
                    continue;
            }
            else if(q.assert_ == "atLeastOne")
            {
                if(!(any_of(q.policySet.cbegin(), q.policySet.cend(), matchPolicySet) ||
                     any_of(q.keyUsage.cbegin(), q.keyUsage.cend(), matchKeyUsageSet) ))
                    continue;
            }
            else
            {
                WARN("Unable to handle Qualifier assert '%s'", q.assert_.c_str());
                continue;
            }

            for(const string &qc: q.qualifiers)
            {
                if(qc == "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement" ||
                   qc == "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig")
                    isQCCompliant = true;
                else if(qc == "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/NotQualified")
                    isQCCompliant = false;
                else if(qc == "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCSSCDStatusAsInCert" ||
                        qc == "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDStatusAsInCert")
                    continue;
                else if(qc == "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD" ||
                        qc == "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD")
                    isQSCD = true;
                else if(qc == "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCNoSSCD" ||
                        qc == "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCNoQSCD")
                    isQSCD = false;
                else if(qc == "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForLegalPerson")
                    DEBUG("QCForLegalPerson qualified?");
                else if(qc == "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESeal")
                    DEBUG("QCForESeal qualified?");
                else if(qc == "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForWSA")
                    DEBUG("QCForWSA qualified?");
            }
        }

        if(!isQCCompliant || !isQSCD)
        {
            Exception e(EXCEPTION_PARAMS("Signing certificate does not meet Qualification requirements"));
            e.setCode(Exception::CertificateIssuerMissing);
            throw e;
        }

        return true;
    }

    int err = X509_STORE_CTX_get_error(csc.get());
    Exception e(EXCEPTION_PARAMS(X509_verify_cert_error_string(err)), OpenSSLException());
    switch(err)
    {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        e.setCode(Exception::CertificateIssuerMissing);
        throw e;
    default: throw e;
    }
}
