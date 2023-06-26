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
OCSP::OCSP(const X509Cert &cert, const X509Cert &issuer)
{
    if(!cert)
        THROW("Can not check X.509 certificate, certificate is NULL pointer.");
    if(!issuer)
        THROW("Can not check X.509 certificate, issuer certificate is NULL pointer.");

    string url = Conf::instance()->ocsp(cert.issuerName("CN"));
    if(url.empty())
    {
        STACK_OF(OPENSSL_STRING) *urls = X509_get1_ocsp(cert.handle());
        if(sk_OPENSSL_STRING_num(urls) > 0)
            url = sk_OPENSSL_STRING_value(urls, 0);
        X509_email_free(urls);
    }
    DEBUG("OCSP url %s", url.c_str());
    if(url.empty())
    {
        Exception e(EXCEPTION_PARAMS("Failed to find ocsp responder url."));
        e.setCode(Exception::OCSPResponderMissing);
        throw e;
    }

    OCSP_CERTID *certId = OCSP_cert_to_id(nullptr, cert.handle(), issuer.handle());
    SCOPE(OCSP_REQUEST, req, OCSP_REQUEST_new());
    if(!req)
        THROW_OPENSSLEXCEPTION("Failed to create new OCSP request, out of memory?");

    if(!OCSP_request_add0_id(req.get(), certId))
        THROW_OPENSSLEXCEPTION("Failed to add certificate ID to OCSP request.");

    SCOPE(ASN1_OCTET_STRING, st, ASN1_OCTET_STRING_new());
    ASN1_OCTET_STRING_set(st.get(), nullptr, 20);
    RAND_bytes(st->data, st->length);

    SCOPE(X509_EXTENSION, ex, X509_EXTENSION_create_by_NID(nullptr, NID_id_pkix_OCSP_Nonce, 0, st.get()));
    if(!OCSP_REQUEST_add_ext(req.get(), ex.get(), 0))
        THROW_OPENSSLEXCEPTION("Failed to add NONCE to OCSP request.");

    Connect::Result result = Connect(url, "POST").exec({
        {"Content-Type", "application/ocsp-request"},
        {"Accept", "application/ocsp-response"},
        {"Connection", "Close"},
        {"Cache-Control", "no-cache"}
    }, i2d(req.get(), i2d_OCSP_REQUEST));

    if(result.isForbidden())
        THROW("OCSP service responded - Forbidden");
    if(!result)
        THROW("Failed to send OCSP request");
    const unsigned char *p2 = (const unsigned char*)result.content.c_str();
    resp.reset(d2i_OCSP_RESPONSE(nullptr, &p2, long(result.content.size())), OCSP_RESPONSE_free);

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

    basic.reset(OCSP_response_get1_basic(resp.get()), OCSP_BASICRESP_free);
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
{
    if(size == 0)
        return;
    resp.reset(d2i_OCSP_RESPONSE(nullptr, &data, long(size)), OCSP_RESPONSE_free);
    if(resp)
       basic.reset(OCSP_response_get1_basic(resp.get()), OCSP_BASICRESP_free);
}

bool OCSP::compareResponderCert(const X509Cert &cert) const
{
    if(!basic || !cert)
        return false;
    const ASN1_OCTET_STRING *hash {};
    const X509_NAME *name {};
    OCSP_resp_get0_id(basic.get(), &hash, &name);
    if(name)
        return X509_NAME_cmp(X509_get_subject_name(cert.handle()), name) == 0;
    if(hash)
    {
        std::array<unsigned char,SHA_DIGEST_LENGTH> sha1{};
        ASN1_BIT_STRING *key = X509_get0_pubkey_bitstr(cert.handle());
        SHA1(key->data, size_t(key->length), sha1.data());
        return sha1.size() == hash->length && memcmp(hash->data, sha1.data(), sha1.size()) == 0;
    }
    return false;
}

X509Cert OCSP::responderCert() const
{
    if(!basic)
        return X509Cert();
    const STACK_OF(X509) *certs = OCSP_resp_get0_certs(basic.get());
    for(int i = 0; i < sk_X509_num(certs); ++i)
    {
        X509Cert cert(sk_X509_value(certs, i));
        if(compareResponderCert(cert))
            return cert;
    }
    for(const X509Cert &cert: X509CertStore::instance()->certs(X509CertStore::OCSP))
    {
        if(compareResponderCert(cert))
            return cert;
    }
    return X509Cert();
}

OCSP::operator vector<unsigned char>() const
{
    return i2d(resp.get(), i2d_OCSP_RESPONSE);
}

/**
 * Check that response was signed with trusted OCSP certificate
 */
void OCSP::verifyResponse(const X509Cert &cert) const
{
    if(!resp)
        THROW("Failed to verify OCSP response.");

    tm tm = producedAt();
    time_t t = util::date::mkgmtime(tm);
    SCOPE(X509_STORE, store, X509CertStore::createStore(X509CertStore::OCSP, &t));
    STACK_OF(X509) *stack = sk_X509_new_null();
    for(const X509Cert &i: X509CertStore::instance()->certs(X509CertStore::OCSP))
    {
        if(compareResponderCert(i))
            sk_X509_push(stack, i.handle());
    }
    int result = OCSP_basic_verify(basic.get(), stack, store.get(), OCSP_NOCHECKS);
    sk_X509_free(stack);
    if(result != 1)
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
        SCOPE(OCSP_CERTID, certId, OCSP_cert_to_id(evp_md, cert.handle(), issuer.handle()));
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
    if(!basic)
        return {};
    int resp_idx = OCSP_BASICRESP_get_ext_by_NID(basic.get(), NID_id_pkix_OCSP_Nonce, -1);
    if(resp_idx < 0)
        return {};
    X509_EXTENSION *ext = OCSP_BASICRESP_get_ext(basic.get(), resp_idx);
    if(!ext)
        return {};

    ASN1_OCTET_STRING *value = X509_EXTENSION_get_data(ext);
    vector<unsigned char> nonce(value->data, value->data + value->length);
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
    if(!basic)
        return {};
    tm tm {};
    ASN1_TIME_to_tm(OCSP_resp_get0_produced_at(basic.get()), &tm);
    return tm;
}
