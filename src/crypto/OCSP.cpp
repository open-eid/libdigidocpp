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

#include "OCSP.h"

#include "Conf.h"
#include "Container.h"
#include "crypto/Connect.h"
#include "crypto/OpenSSLHelpers.h"
#include "crypto/X509CertStore.h"
#include "util/DateTime.h"
#include "util/log.h"

#include <algorithm>
#include <array>

#ifdef WIN32 //hack for win32 build
#undef OCSP_REQUEST
#undef OCSP_RESPONSE
#endif
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

using namespace digidoc;
using namespace std;

/**
 * Initialize OCSP certificate validator.
 */
OCSP::OCSP(const X509Cert &cert, const X509Cert &issuer, const std::string &userAgent)
    : resp(nullptr, OCSP_RESPONSE_free)
    , basic(nullptr, OCSP_BASICRESP_free)
{
    if(!cert)
        THROW("Can not check X.509 certificate, certificate is NULL pointer.");
    if(!issuer)
        THROW("Can not check X.509 certificate, issuer certificate is NULL pointer.");

    string url = Conf::instance()->ocsp(cert.issuerName("CN"));
    if(url.empty())
    {
        if(auto urls = make_unique_ptr<X509_email_free>(X509_get1_ocsp(cert.handle()));
            urls && sk_OPENSSL_STRING_num(urls.get()) > 0)
            url = sk_OPENSSL_STRING_value(urls.get(), 0);
    }
    DEBUG("OCSP url %s", url.c_str());
    if(url.empty())
    {
        Exception e(EXCEPTION_PARAMS("Failed to find ocsp responder url."));
        e.setCode(Exception::OCSPResponderMissing);
        throw e;
    }

    auto req = make_unique_ptr<OCSP_REQUEST_free>(OCSP_REQUEST_new());
    if(!req)
        THROW_OPENSSLEXCEPTION("Failed to create new OCSP request, out of memory?");

    OCSP_CERTID *certId = OCSP_cert_to_id(nullptr, cert.handle(), issuer.handle());
    if(!OCSP_request_add0_id(req.get(), certId))
        THROW_OPENSSLEXCEPTION("Failed to add certificate ID to OCSP request.");

    if(!OCSP_request_add1_nonce(req.get(), nullptr, 32)) // rfc8954: SIZE(1..32)
        THROW_OPENSSLEXCEPTION("Failed to add NONCE to OCSP request.");

    Connect::Result result = Connect(url, "POST", 0, {}, userAgent, "1.0").exec({
        {"Content-Type", "application/ocsp-request"},
        {"Accept", "application/ocsp-response"},
        {"Connection", "Close"},
        {"Cache-Control", "no-cache"}
    }, i2d<i2d_OCSP_REQUEST>(req));

    if(result.isForbidden())
        THROW("OCSP service responded - Forbidden");
    if(!result)
        THROW("Failed to send OCSP request");
    const auto *p2 = (const unsigned char*)result.content.c_str();
    resp.reset(d2i_OCSP_RESPONSE(nullptr, &p2, long(result.content.size())));

    switch(int respStatus = OCSP_response_status(resp.get()))
    {
    case OCSP_RESPONSE_STATUS_SUCCESSFUL: break;
    case OCSP_RESPONSE_STATUS_UNAUTHORIZED:
    {
        Exception e(EXCEPTION_PARAMS("OCSP request failed"));
        e.setCode(Exception::OCSPRequestUnauthorized);
        throw e;
    }
    default:
        THROW("OCSP request failed, response status: %s", OCSP_response_status_str(respStatus));
    }

    basic.reset(OCSP_response_get1_basic(resp.get()));
    if(!basic)
        THROW("Incorrect OCSP response.");

    if(OCSP_check_nonce(req.get(), basic.get()) <= 0)
        THROW("Incorrect NONCE field value.");

    ASN1_GENERALIZEDTIME *thisUpdate {}, *nextUpdate {};
    if(OCSP_resp_find_status(basic.get(), certId, nullptr, nullptr, nullptr, &thisUpdate, &nextUpdate) != 1)
        THROW("Failed to find CERT_ID from OCSP response.");

    DEBUG("OCSP producedAt: %s", util::date::to_string(producedAt()).c_str());
    if(!OCSP_check_validity(thisUpdate, nextUpdate, 15*60, 2*60))
    {
        Exception e(EXCEPTION_PARAMS("OCSP response not in valid time slot."));
        e.setCode(Exception::OCSPTimeSlot);
        throw e;
    }
}

OCSP::OCSP(const unsigned char *data, size_t size)
    : resp(nullptr, OCSP_RESPONSE_free)
    , basic(nullptr, OCSP_BASICRESP_free)
{
    if(size == 0)
        return;
    resp.reset(d2i_OCSP_RESPONSE(nullptr, &data, long(size)));
    if(resp)
        basic.reset(OCSP_response_get1_basic(resp.get()));
}

bool OCSP::compareResponderCert(const X509Cert &cert) const
{
    if(!basic || !cert)
        return false;

    const ASN1_OCTET_STRING *hash {};
    const X509_NAME *name {};
    if(OCSP_resp_get0_id(basic.get(), &hash, &name) != 1)
        return false;
    if(hash)
    {
        std::array<unsigned char,SHA_DIGEST_LENGTH> sha1{};
        ASN1_BIT_STRING *key = X509_get0_pubkey_bitstr(cert.handle());
        SHA1(key->data, size_t(key->length), sha1.data());
        if(!equal(sha1.cbegin(), sha1.cend(), hash->data, std::next(hash->data, hash->length)))
            return false;
    }
    else if(X509_NAME_cmp(X509_get_subject_name(cert.handle()), name) != 0)
        return false;

    const ASN1_OBJECT *sigalg {};
    X509_ALGOR_get0(&sigalg, nullptr, nullptr, OCSP_resp_get0_tbs_sigalg(basic.get()));
    int pknid = 0;
    return OBJ_find_sigid_algs(OBJ_obj2nid(sigalg), nullptr, &pknid) == 1 &&
        EVP_PKEY_is_a(X509_get0_pubkey(cert.handle()), OBJ_nid2sn(pknid)) == 1;
}

X509Cert OCSP::responderCert() const
{
    if(!basic)
        return X509Cert();
    if(X509 *signer{}; OCSP_resp_get0_signer(basic.get(), &signer, nullptr) != 0 && signer)
        return X509Cert(signer);
    for(const X509Cert &cert: X509CertStore::instance()->certs(X509CertStore::OCSP))
    {
        if(compareResponderCert(cert))
            return cert;
    }
    return X509Cert();
}

OCSP::operator vector<unsigned char>() const
{
    return i2d<i2d_OCSP_RESPONSE>(resp);
}

/**
 * Check that response was signed with trusted OCSP certificate
 */
void OCSP::verifyResponse(const X509Cert &cert) const
{
    if(!basic)
        THROW("Failed to verify OCSP response.");

    tm tm = producedAt();
    auto stack = make_unique_ptr(sk_X509_new_null(), [](auto *sk) { sk_X509_free(sk); });
    // Some OCSP-s do not have certificates in response and stack is used for finding certificate for this
    if(X509 *signer{}; OCSP_resp_get0_signer(basic.get(), &signer, nullptr) == 0 || !signer)
    {
        for(const X509Cert &i: X509CertStore::instance()->certs(X509CertStore::OCSP))
        {
            if(compareResponderCert(i))
                sk_X509_push(stack.get(), i.handle());
        }
    }
    auto store = X509CertStore::createStore(X509CertStore::OCSP, tm);
    if(OCSP_basic_verify(basic.get(), stack.get(), store.get(), OCSP_NOCHECKS | OCSP_PARTIAL_CHAIN) != 1)
    {
        unsigned long err = ERR_get_error();
        if(ERR_GET_LIB(err) == ERR_LIB_OCSP &&
            (ERR_GET_REASON(err) == OCSP_R_CERTIFICATE_VERIFY_ERROR ||
             ERR_GET_REASON(err) == OCSP_R_SIGNER_CERTIFICATE_NOT_FOUND))
        {
            OpenSSLException e(EXCEPTION_PARAMS("Failed to verify OCSP Responder certificate"), err);
            e.setCode(Exception::CertificateUnknown);
            throw e;
        }
        throw OpenSSLException(EXCEPTION_PARAMS("Failed to verify OCSP response."), err);
    }

    // Find issuer before OCSP validation to activate region TSL
    X509Cert issuer = X509CertStore::instance()->findIssuer(cert, X509CertStore::CA);
    if(!issuer)
    {
        Exception e(EXCEPTION_PARAMS("Certificate status: unknown"));
        e.setCode(Exception::CertificateUnknown);
        throw e;
    }

    int status = V_OCSP_CERTSTATUS_UNKNOWN;
    for(int i = 0, count = OCSP_resp_count(basic.get()); i < count; ++i)
    {
        const EVP_MD *evp_md {};
        const OCSP_CERTID *certID = OCSP_SINGLERESP_get0_id(OCSP_resp_get0(basic.get(), i));
        ASN1_OBJECT *md {};
        if(OCSP_id_get0_info(nullptr, &md, nullptr, nullptr, const_cast<OCSP_CERTID*>(certID)) == 1)
            evp_md = EVP_get_digestbyobj(md);
        auto certId = make_unique_ptr<OCSP_CERTID_free>(OCSP_cert_to_id(evp_md, cert.handle(), issuer.handle()));
        if(OCSP_resp_find_status(basic.get(), certId.get(), &status, nullptr, nullptr, nullptr, nullptr) == 1)
            break;
    }

    switch(status)
    {
    case V_OCSP_CERTSTATUS_GOOD: break;
    case V_OCSP_CERTSTATUS_REVOKED:
    {
        DEBUG("OCSP status: REVOKED");
        Exception e(EXCEPTION_PARAMS("Certificate status: revoked"));
        e.setCode(Exception::CertificateRevoked);
        throw e;
    }
    case V_OCSP_CERTSTATUS_UNKNOWN:
    default:
    {
        DEBUG("OCSP status: UNKNOWN");
        Exception e(EXCEPTION_PARAMS("Certificate status: unknown"));
        e.setCode( Exception::CertificateUnknown );
        throw e;
    }
    }
}

/**
 * Return OCSP nonce
 */
vector<unsigned char> OCSP::nonce() const
{
    vector<unsigned char> nonce;
    if(!basic)
        return nonce;
    int resp_idx = OCSP_BASICRESP_get_ext_by_NID(basic.get(), NID_id_pkix_OCSP_Nonce, -1);
    if(resp_idx < 0)
        return nonce;
    X509_EXTENSION *ext = OCSP_BASICRESP_get_ext(basic.get(), resp_idx);
    if(!ext)
        return nonce;

    ASN1_OCTET_STRING *value = X509_EXTENSION_get_data(ext);
    nonce.assign(value->data, std::next(value->data, value->length));
    //OpenSSL OCSP created messages NID_id_pkix_OCSP_Nonce field is DER encoded twice, not a problem with java impl
    //XXX: UglyHackTM check if nonceAsn1 contains ASN1_OCTET_STRING
    //XXX: if first 2 bytes seem to be beginning of DER ASN1_OCTET_STRING then remove them
    // We assume that bdoc nonce has always octet string header
    if(nonce.size() > 2 && nonce[0] == V_ASN1_OCTET_STRING && nonce[1] == nonce.size()-2)
        nonce.erase(nonce.begin(), nonce.begin() + 2);
    return nonce;
}

tm OCSP::producedAt() const
{
    tm tm {};
    if(!basic)
        return tm;
    ASN1_TIME_to_tm(OCSP_resp_get0_produced_at(basic.get()), &tm);
    return tm;
}
