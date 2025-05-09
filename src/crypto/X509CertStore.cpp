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
#include "crypto/Connect.h"
#include "crypto/OpenSSLHelpers.h"
#include "crypto/TSL.h"
#include "util/algorithm.h"
#include "util/DateTime.h"
#include "util/log.h"

#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

using namespace digidoc;
using namespace std;

const X509CertStore::Type X509CertStore::CA {
    "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
};

const X509CertStore::Type X509CertStore::TSA {
    "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST",
};

const X509CertStore::Type X509CertStore::OCSP {
    "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
    "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC",
};

class X509CertStore::Private: public vector<TSL::Service> {
public:
    void update()
    {
        vector<TSL::Service> list = TSL::parse();
        swap(list);
        INFO("Loaded %zu certificates into TSL certificate store.", size());
    }
};

/**
 * X509CertStore constructor.
 */
X509CertStore::X509CertStore()
    : d(make_unique<Private>())
{
    d->update();
}

/**
 * Release all certificates.
 */
X509CertStore::~X509CertStore() = default;

void X509CertStore::activate(const X509Cert &cert) const
{
    if(std::max<bool>(TSL::activate(cert.issuerName("C")), TSL::activate(cert.subjectName("C"))))
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

vector<X509Cert> X509CertStore::certs(const Type &type) const
{
    vector<X509Cert> certs;
    for(const TSL::Service &s: *d)
    {
        if(type.find(s.type) != type.cend())
            certs.insert(certs.cend(), s.certs.cbegin(), s.certs.cend());
    }
    return certs;
}

X509Cert X509CertStore::findIssuer(const X509Cert &cert, const Type &type) const
{
    activate(cert);
    for(const TSL::Service &s: *d)
    {
        if(type.find(s.type) == type.cend())
            continue;
        for(const X509Cert &i: s.certs)
        {
            if(X509_check_issued(i.handle(), cert.handle()) == X509_V_OK)
                return i;
        }
    }
    return X509Cert();
}

X509Cert X509CertStore::issuerFromAIA(const X509Cert &cert)
{
    SCOPE(AUTHORITY_INFO_ACCESS, aia, X509_get_ext_d2i(cert.handle(), NID_info_access, nullptr, nullptr));
    if(!aia)
        return X509Cert();
    string url;
    for(int i = 0; i < sk_ACCESS_DESCRIPTION_num(aia.get()); ++i)
    {
        if(ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(aia.get(), i);
            ad->location->type == GEN_URI &&
            OBJ_obj2nid(ad->method) == NID_ad_ca_issuers)
            url.assign((const char*)ad->location->d.uniformResourceIdentifier->data, ad->location->d.uniformResourceIdentifier->length);
    }
    if(url.empty())
        return X509Cert();
    Connect::Result result = Connect(url, "GET").exec();
    return X509Cert((const unsigned char*)result.content.c_str(), result.content.size());
}

unique_free_t<X509_STORE> X509CertStore::createStore(const Type &type, tm &tm)
{
    SCOPE(X509_STORE, store, X509_STORE_new());
    if (!store)
        THROW_OPENSSLEXCEPTION("Failed to create X509_STORE_CTX");
    X509_STORE_set_verify_cb(store.get(), X509CertStore::validate);
    X509_STORE_set_ex_data(store.get(), 0, const_cast<Type*>(&type));
    X509_STORE_set_flags(store.get(), X509_V_FLAG_USE_CHECK_TIME | X509_V_FLAG_PARTIAL_CHAIN);
    X509_VERIFY_PARAM_set_time(X509_STORE_get0_param(store.get()), util::date::mkgmtime(tm));
    return store;
}

int X509CertStore::validate(int ok, X509_STORE_CTX *ctx)
{
    switch(X509_STORE_CTX_get_error(ctx))
    {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    case X509_V_ERR_CERT_UNTRUSTED:
        break;
    default: return ok;
    }

    auto *type = static_cast<Type*>(X509_STORE_get_ex_data(X509_STORE_CTX_get0_store(ctx), 0));
    X509 *x509 = X509_STORE_CTX_get0_cert(ctx);
    auto current = util::date::to_string(X509_VERIFY_PARAM_get_time(X509_STORE_CTX_get0_param(ctx)));
    for(const TSL::Service &s: *instance()->d)
    {
        if(type->find(s.type) == type->cend()) // correct service type
            continue;
        if(none_of(s.certs, [&](const X509Cert &issuer) {
                if(issuer == x509) // certificate is listed by service
                    return true;
                if(X509_check_issued(issuer.handle(), x509) != X509_V_OK) // certificate is issued by service
                    return false;
                SCOPE(EVP_PKEY, pub, X509_get_pubkey(issuer.handle()));
                if(X509_verify(x509, pub.get()) == 1) // certificate is signed by service
                    return true;
                ERR_clear_error();
                return false;
            })) // certificate is trusted by service
            continue;
        for(auto i = s.validity.crbegin(), end = s.validity.crend(); i != end; ++i)
        {
            if(current < i->first) // Search older status
                continue;
            if(!i->second.has_value()) // Has revoked
                break;
            X509_STORE_CTX_set_ex_data(ctx, 0, const_cast<TSL::Qualifiers*>(&i->second));
            return 1;
        }
    }
    return ok;
}

/**
 * Check if X509Cert is signed by trusted issuer
 * @throw Exception if error
 */
bool X509CertStore::verify(const X509Cert &cert, bool noqscd, tm validation_time) const
{
    activate(cert);
    if(util::date::is_empty(validation_time))
        ASN1_TIME_to_tm(X509_get0_notBefore(cert.handle()), &validation_time);
    auto store = createStore(X509CertStore::CA, validation_time);
    SCOPE(X509_STORE_CTX, csc, X509_STORE_CTX_new());
    if(!X509_STORE_CTX_init(csc.get(), store.get(), cert.handle(), nullptr))
        THROW_OPENSSLEXCEPTION("Failed to init X509_STORE_CTX");
    if(X509_verify_cert(csc.get()) <= 0)
    {
        int err = X509_STORE_CTX_get_error(csc.get());
        OpenSSLException e(EXCEPTION_PARAMS("%s", X509_verify_cert_error_string(err)));
        if(err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
            e.setCode(Exception::CertificateIssuerMissing);
        throw e;
    }

    if(noqscd)
        return true;

    const auto *qualifiers = static_cast<const TSL::Qualifiers*>(X509_STORE_CTX_get_ex_data(csc.get(), 0));
    const vector<string> policies = cert.certificatePolicies();
    const vector<string> qcstatement = cert.qcStatements();
    const vector<X509Cert::KeyUsage> keyUsage = cert.keyUsage();
    bool isQCCompliant = contains(qcstatement, X509Cert::QC_COMPLIANT);
    bool isQSCD =
        contains(policies, X509Cert::QCP_PUBLIC_WITH_SSCD) ||
        contains(policies, X509Cert::QCP_LEGAL_QSCD) ||
        contains(policies, X509Cert::QCP_NATURAL_QSCD) ||
        contains(qcstatement, X509Cert::QC_SSCD);

    bool isESeal = // Special treamtent for E-Seals
        contains(policies, X509Cert::QCP_LEGAL) ||
        contains(qcstatement, X509Cert::QCT_ESEAL);
    auto matchPolicySet = [&policies](const vector<string> &policySet) {
        return all_of(policySet, [&policies](const string &policy) {
            return contains(policies, policy);
        });
    };
    auto matchKeyUsageSet = [&keyUsage](const map<X509Cert::KeyUsage,bool> &keyUsageSet) {
        return all_of(keyUsageSet, [&keyUsage](pair<X509Cert::KeyUsage, bool> keyUsageBit) {
            return contains(keyUsage, keyUsageBit.first) == keyUsageBit.second;
        });
    };

    for(const TSL::Qualifier &q: qualifiers->value())
    {
        if(q.assert_ == "all")
        {
            if(!(all_of(q.policySet, matchPolicySet) &&
                 all_of(q.keyUsage, matchKeyUsageSet)))
                continue;
        }
        else if(q.assert_ == "atLeastOne")
        {
            if(!(any_of(q.policySet, matchPolicySet) ||
                 any_of(q.keyUsage, matchKeyUsageSet)))
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
            else if(qc == "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForLegalPerson" ||
                    qc == "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESeal")
                isESeal = true;
        }
    }

    if((isQCCompliant && isQSCD) || isESeal)
        return true;
    Exception e(EXCEPTION_PARAMS("Signing certificate does not meet Qualification requirements"));
    e.setCode(Exception::CertificateIssuerMissing);
    throw e;
}
