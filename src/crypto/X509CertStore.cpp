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
#include "util/File.h"
#include "util/log.h"

#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#ifndef _WIN32
#include <dlfcn.h>
#endif

using namespace digidoc;
using namespace std;

namespace {

int storeTypeIndex()
{
    static const int index = X509_STORE_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    return index;
}

int storeContextValidityIndex()
{
    static const int index = X509_STORE_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    return index;
}

bool verifyLegacySignature(X509 *cert, EVP_PKEY *key)
{
#ifndef _WIN32
    if(int digest = NID_undef;
       cert && key && OBJ_find_sigid_algs(X509_get_signature_nid(cert), &digest, nullptr) == 1 && digest == NID_sha1)
    {
        // X509_verify uses the certificate's context, not X509_STORE_CTX.
        if(auto local = X509CertStore::legacyCertificate(cert); local && X509_verify(local.get(), key) == 1)
            return true;
    }
#endif
    return false;
}

bool issuedBy(X509 *cert, const X509Cert &issuer)
{
    if(X509_check_issued(issuer.handle(), cert) == X509_V_OK)
    {
        auto *key = X509_get0_pubkey(issuer.handle());
        if(X509_verify(cert, key) == 1 || verifyLegacySignature(cert, key))
            return true;
    }
    ERR_clear_error();
    return false;
}

bool validAt(X509 *cert, time_t time)
{
    return X509_cmp_time(X509_get0_notBefore(cert), &time) < 0 &&
        X509_cmp_time(X509_get0_notAfter(cert), &time) > 0;
}

}

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

struct X509CertStore::Private: public vector<TSL::Service>
{
    void enumServices(const Type &type, const string &time, const auto &callback) const
    {
        for(const TSL::Service &service: *this)
        {
            auto i = service.validity.upper_bound(time);
            if(i == service.validity.cbegin())
                continue;
            --i;
            if(i->second && contains(type, i->second->type) && callback(service, *i->second))
                return;
        }
    }
};

/**
 * X509CertStore constructor.
 */
X509CertStore::X509CertStore()
    : d(make_unique<Private>())
{}

/**
 * Release all certificates.
 */
X509CertStore::~X509CertStore() noexcept = default;

void X509CertStore::activate(const X509Cert &cert) const try
{
    if(std::max<bool>(TSL::activate(cert.issuerName("C")), TSL::activate(cert.subjectName("C"))))
        update();
}
catch(const Exception &e)
{
    ERR("Failed to activate TSL: %s", e.msg().c_str()); 
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
        if(any_of(s.validity, [&type](const auto &v) {
                return v.second && contains(type, v.second->type);
            }))
            certs.insert(certs.cend(), s.certs.cbegin(), s.certs.cend());
    }
    return certs;
}

X509Cert X509CertStore::findIssuer(const X509Cert &cert, const Type &type) const
{
    activate(cert);
    for(const TSL::Service &s: *d)
    {
        if(!any_of(s.validity, [&type](const auto &v) {
                return v.second && contains(type, v.second->type);
            }))
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
    auto aia = make_unique_cast<AUTHORITY_INFO_ACCESS_free>(X509_get_ext_d2i(cert.handle(), NID_info_access, nullptr, nullptr));
    if(!aia)
        return X509Cert();
    string url;
    for(int i = 0; i < sk_ACCESS_DESCRIPTION_num(aia.get()); ++i)
    {
        if(ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(aia.get(), i);
            ad->location->type == GEN_URI &&
            OBJ_obj2nid(ad->method) == NID_ad_ca_issuers)
        {
            const unsigned char *data = ASN1_STRING_get0_data(ad->location->d.uniformResourceIdentifier);
            url.assign((const char*)data, ASN1_STRING_length(ad->location->d.uniformResourceIdentifier));
        }
    }
    if(url.empty())
        return X509Cert();
    Connect::Result result = Connect(url, "GET").exec();
    return X509Cert((const unsigned char*)result.content.c_str(), result.content.size());
}

unique_free_t<X509_STORE> X509CertStore::createStore(const Type &type, tm &tm)
{
    auto store = make_unique_ptr(X509_STORE_new(), X509_STORE_free);
    if (!store)
        THROW_OPENSSLEXCEPTION("Failed to create X509_STORE_CTX");
    X509_STORE_set_verify_cb(store.get(), X509CertStore::validate);
    X509_STORE_set_get_issuer(store.get(), [](X509 **issuer, X509_STORE_CTX *ctx, auto *cert) {
        return X509CertStore::getIssuer(issuer, ctx, const_cast<X509*>(cert));
    });
    const int typeIndex = storeTypeIndex();
    const int validityIndex = storeContextValidityIndex();
    if(typeIndex < 0 || validityIndex < 0 ||
       X509_STORE_set_ex_data(store.get(), typeIndex, const_cast<Type*>(&type)) != 1)
        THROW_OPENSSLEXCEPTION("Failed to initialize X509 store application data");
    X509_STORE_set_flags(store.get(), X509_V_FLAG_USE_CHECK_TIME | X509_V_FLAG_PARTIAL_CHAIN);
    X509_VERIFY_PARAM_set_time(X509_STORE_get0_param(store.get()), util::date::mkgmtime(tm));
    return store;
}

unique_free_t<X509> X509CertStore::legacyCertificate(X509 *cert)
{
#ifndef _WIN32
    // Fedora/RHEL can disable SHA-1 even for historical certificate and OCSP signatures.
    // Keep that exception in a private context, leaving the caller's policy intact.
    static const auto context = [] {
        auto ctx = make_unique_ptr<OSSL_LIB_CTX_free>(nullptr);
        auto *allow = reinterpret_cast<int(*)(void*, int, int)>(
            dlsym(RTLD_DEFAULT, "ossl_ctx_legacy_digest_signatures_allowed_set"));
        if(!allow)
            return ctx;
        ctx.reset(OSSL_LIB_CTX_new());
        if(!ctx || OSSL_LIB_CTX_load_config(ctx.get(), nullptr) != 1 || allow(ctx.get(), 1, 0) != 1)
        {
            WARN("Failed to enable legacy certificate verification in private OpenSSL context");
            ctx.reset();
        }
        return ctx;
    }();
    if(context)
    {
        ERR_clear_error();
        auto der = i2d<i2d_X509>(cert);
        X509 *local = X509_new_ex(context.get(), nullptr);
        // d2i_X509 frees local and sets it to nullptr on failure.
        if(const unsigned char *data = der.data(); local && d2i_X509(&local, &data, long(der.size())))
            return {local, X509_free};
    }
#endif
    return {nullptr, X509_free};
}

int X509CertStore::getIssuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *cert)
{
    *issuer = nullptr;
    const auto *type = static_cast<const Type*>(
        X509_STORE_get_ex_data(X509_STORE_CTX_get0_store(ctx), storeTypeIndex()));
    if(!type)
        return 0;
    auto time = X509_VERIFY_PARAM_get_time(X509_STORE_CTX_get0_param(ctx));
    auto current = util::date::to_string(time);
    X509 *fallback{};
    const TSL::Validity *fallbackValidity{};
    auto useIssuer = [&](X509 *candidate, const TSL::Validity *validity) {
        if(X509_STORE_CTX_set_ex_data(ctx, storeContextValidityIndex(),
                const_cast<TSL::Validity*>(validity)) != 1 || X509_up_ref(candidate) != 1)
            return -1;
        *issuer = candidate;
        return 1;
    };
    int result = 0;
    instance()->d->enumServices(*type, current, [&](const TSL::Service &service, const TSL::Validity &validity) {
        for(const X509Cert &candidate: service.certs)
        {
            if(!issuedBy(cert, candidate))
                continue;
            if(validAt(candidate.handle(), time))
            {
                result = useIssuer(candidate.handle(), &validity);
                return true;
            }
            if(!fallback)
            {
                fallback = candidate.handle();
                fallbackValidity = &validity;
            }
        }
        return false;
    });
    if(result != 0)
        return result;
    return fallback ? useIssuer(fallback, fallbackValidity) : 0;
}

int X509CertStore::validate(int ok, X509_STORE_CTX *ctx)
{
    switch(X509_STORE_CTX_get_error(ctx))
    {
    case X509_V_ERR_CERT_SIGNATURE_FAILURE:
    {
        if(ok)
            return ok;
        auto *chain = X509_STORE_CTX_get0_chain(ctx);
        int depth = X509_STORE_CTX_get_error_depth(ctx);
        int count = sk_X509_num(chain);
        if(depth < 0 || depth >= count)
            return ok;
        X509 *issuer = sk_X509_value(chain, depth + 1 < count ? depth + 1 : depth);
        return verifyLegacySignature(X509_STORE_CTX_get_current_cert(ctx), X509_get0_pubkey(issuer)) ? 1 : ok;
    }
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    case X509_V_ERR_CERT_UNTRUSTED:
        break;
    default: return ok;
    }

    const int typeIndex = storeTypeIndex();
    if(typeIndex < 0)
        return 0;
    auto *type = static_cast<Type*>(X509_STORE_get_ex_data(X509_STORE_CTX_get0_store(ctx), typeIndex));
    if(!type)
        return 0;
    auto current = util::date::to_string(X509_VERIFY_PARAM_get_time(X509_STORE_CTX_get0_param(ctx)));
    auto trusted = [&](X509 *x509) -> const TSL::Validity* {
        const TSL::Validity *result{};
        instance()->d->enumServices(*type, current, [&](const TSL::Service &service, const TSL::Validity &validity) {
            if(none_of(service.certs, [&](const X509Cert &issuer) {
                    return issuer == x509 || issuedBy(x509, issuer); // certificate is listed or issued by service
                })) // certificate is trusted by service
                return false;
            result = &validity;
            return true;
        });
        return result;
    };
    X509 *current_cert = X509_STORE_CTX_get_current_cert(ctx);
    X509 *target_cert = X509_STORE_CTX_get0_cert(ctx);
    const TSL::Validity *validity = current_cert ? trusted(current_cert) : nullptr;
    if(!validity && target_cert && target_cert != current_cert)
        validity = trusted(target_cert);
    if(!validity)
        return ok;
    if(const int validityIndex = storeContextValidityIndex();
        validityIndex < 0 || X509_STORE_CTX_set_ex_data(ctx, validityIndex,
            const_cast<TSL::Validity*>(validity)) != 1)
        return 0;
    return 1;
}

void X509CertStore::update() const
{
    string url = CONF(TSLUrl);
    string cache = CONF(TSLCache);
    vector<X509Cert> cert = CONF(TSLCerts);
    util::File::createDirectory(cache);
    vector<TSL::Service> list = TSL::parse(url, cert, cache, util::File::fileName(url));
    d->swap(list);
    INFO("Loaded %zu certificates into TSL certificate store.", d->size());
}

/**
 * Check if X509Cert is signed by trusted issuer
 * @throw Exception if error
 */
bool X509CertStore::verify(const X509Cert &cert, bool noqscd, tm validation_time, const vector<X509Cert> &untrusted) const
{
    activate(cert);
    if(util::date::is_empty(validation_time))
        ASN1_TIME_to_tm(X509_get0_notBefore(cert.handle()), &validation_time);
    auto store = createStore(X509CertStore::CA, validation_time);
    auto csc = make_unique_ptr<X509_STORE_CTX_free>(X509_STORE_CTX_new());
    auto stack = make_unique_ptr(sk_X509_new_null(), [](auto *sk) { sk_X509_free(sk); });
    for(const X509Cert &i: untrusted)
    {
        if(i)
            sk_X509_push(stack.get(), i.handle());
    }
    if(!X509_STORE_CTX_init(csc.get(), store.get(), cert.handle(), stack.get()))
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

    const auto *v = static_cast<const TSL::Validity*>(
        X509_STORE_CTX_get_ex_data(csc.get(), storeContextValidityIndex()));
    if(!v)
        THROW("Failed to resolve TSL service validity");
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

    for(const TSL::Qualifier &q: v->qualifiers)
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
