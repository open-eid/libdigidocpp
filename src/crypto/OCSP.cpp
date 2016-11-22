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

#include "Container.h"
#include "log.h"
#include "Conf.h"
#include "crypto/OpenSSLHelpers.h"
#include "crypto/X509CertStore.h"
#include "util/DateTime.h"

#include <algorithm>

#include <openssl/pkcs12.h>
#include <openssl/ssl.h>
#ifdef WIN32 //hack for win32 build
#undef OCSP_REQUEST
#undef OCSP_RESPONSE
#endif
#include <openssl/ocsp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#ifdef __APPLE__
#include <Security/Security.h>
#endif

using namespace digidoc;
using namespace std;

/**
 * Initialize OCSP certificate validator.
 */
OCSP::OCSP(const X509Cert &cert, const X509Cert &issuer, const vector<unsigned char> &nonce, const string &useragent)
{
    if(!cert)
        THROW("Can not check X.509 certificate, certificate is NULL pointer.");
    if(!issuer)
        THROW("Can not check X.509 certificate, issuer certificate is NULL pointer.");

    string url = Conf::instance()->ocsp(cert.issuerName("CN"));
    DEBUG("OCSP url %s", url.c_str());
    if(url.empty())
    {
        Exception e(__FILE__, __LINE__, "Failed to find ocsp responder url.");
        e.setCode(Exception::OCSPResponderMissing);
        throw e;
    }

    OCSP_CERTID *certId = OCSP_cert_to_id(0, cert.handle(), issuer.handle());
    SCOPE(OCSP_REQUEST, req, createRequest(certId, nonce));
    resp.reset(sendRequest(url, req.get(), useragent), function<void(OCSP_RESPONSE*)>(OCSP_RESPONSE_free));

    switch(int respStatus = OCSP_response_status(resp.get()))
    {
    case OCSP_RESPONSE_STATUS_SUCCESSFUL: break;
    case OCSP_RESPONSE_STATUS_UNAUTHORIZED:
    {
        Exception e(__FILE__, __LINE__, "OCSP request failed");
        e.setCode(Exception::OCSPRequestUnauthorized);
        throw e;
    }
    default:
        THROW("OCSP request failed, response status: %s", OCSP_response_status_str(respStatus));
    }

    basic.reset(OCSP_response_get1_basic(resp.get()), function<void(OCSP_BASICRESP*)>(OCSP_BASICRESP_free));
    if(!basic)
        THROW("Incorrect OCSP response.");

    if(OCSP_check_nonce(req.get(), basic.get()) <= 0)
        THROW("Incorrect NONCE field value.");

    int certStatus = -1; int reason = -1;
    ASN1_GENERALIZEDTIME *producedAt = nullptr, *thisUpdate = nullptr, *nextUpdate = nullptr;
    if(!OCSP_resp_find_status(basic.get(), certId, &certStatus, &reason, &producedAt, &thisUpdate, &nextUpdate))
        THROW("Failed to get status code from OCSP response.");

#if 0
    if(!OCSP_check_validity(thisUpdate, nextUpdate, 15*60, 2*60))
    {
        Exception e(__FILE__, __LINE__, "OCSP response not in valid time slot.");
        e.setCode(Exception::OCSPTimeSlot);
        throw e;
    }
#endif
}

OCSP::OCSP(const vector<unsigned char> &data)
{
    if(data.empty())
        return;
    const unsigned char *p = data.data();
    resp.reset(d2i_OCSP_RESPONSE(0, &p, (unsigned int)data.size()), function<void(OCSP_RESPONSE*)>(OCSP_RESPONSE_free));
    if(resp)
       basic.reset(OCSP_response_get1_basic(resp.get()), function<void(OCSP_BASICRESP*)>(OCSP_BASICRESP_free));
}

bool OCSP::compareResponderCert(const X509Cert &cert) const
{
    if(!basic || !cert)
        return false;
    OCSP_RESPID *respID = basic->tbsResponseData->responderId;
    switch(respID->type)
    {
    case V_OCSP_RESPID_NAME:
        return X509_NAME_cmp(X509_get_subject_name(cert.handle()), respID->value.byName) == 0;
    case V_OCSP_RESPID_KEY:
    {
        unsigned char sha1[SHA_DIGEST_LENGTH];
        ASN1_BIT_STRING *key = cert.handle()->cert_info->key->public_key;
        return EVP_Digest(key->data, key->length, sha1, nullptr, EVP_sha1(), nullptr) == 1 &&
            memcmp(respID->value.byKey->data, &sha1, respID->value.byKey->length) == 0;
    }
    default: return false;
    }
}

/**
 * Creates OCSP request to check the certificate <code>cert</code> validity.
 *
 * @param certId OCSP_CERTID which validity will be checked.
 * @param nonce NONCE field value in OCSP request.
 * @return returns created OCSP request.
 */
OCSP_REQUEST* OCSP::createRequest(OCSP_CERTID *certId, const vector<unsigned char> &nonce)
{
    SCOPE(OCSP_REQUEST, req, OCSP_REQUEST_new());
    if(!req)
        THROW_OPENSSLEXCEPTION("Failed to create new OCSP request, out of memory?");

    if(!OCSP_request_add0_id(req.get(), certId))
        THROW_OPENSSLEXCEPTION("Failed to add certificate ID to OCSP request.");

#ifdef OCSP_NATIVE_NONCE
    if(OCSP_request_add1_nonce(req.get(), const_cast<unsigned char*>(nonce.data()), int(nonce.size())) <= 0)
        THROW_OPENSSLEXCEPTION("Failed to add NONCE to OCSP request.");
#else
    ASN1_OCTET_STRING *st = ASN1_OCTET_STRING_new();
    if(nonce.empty())
    {
        st->length = 20;
        st->data = (unsigned char*)OPENSSL_malloc(st->length);
        RAND_bytes(st->data, st->length);
    }
    else
    {
        ASN1_OCTET_STRING_set(st, nonce.data(), nonce.size());
        X509_EXTENSION *ex = X509_EXTENSION_create_by_NID(0, NID_id_pkix_OCSP_Nonce, 0, st);
        ASN1_OCTET_STRING_free(st);
        if(!OCSP_REQUEST_add_ext(req.get(), ex, 0))
            THROW_OPENSSLEXCEPTION("Failed to add NONCE to OCSP request.");
    }
#endif

    Conf *c = Conf::instance();
    if(!c->PKCS12Disable())
    {
        X509* signCert;
        EVP_PKEY* signKey;
#ifdef USE_KEYCHAIN
        if(SecIdentityRef identity = SecIdentityCopyPreferred( CFSTR("ocsp.sk.ee"), 0, 0 ))
        {
            SecCertificateRef certref = nullptr;
            SecKeyRef keyref = nullptr;
            SecIdentityCopyCertificate(identity, &certref);
            SecIdentityCopyPrivateKey(identity, &keyref);
            CFRelease(identity);
            if(!certref || !keyref)
                THROW("Failed to read PKCS12 data");

            CFDataRef certdata = SecCertificateCopyData(certref);
            CFRelease(certref);
            if(!certdata)
                THROW("Failed to read PKCS12 certificate");
            const unsigned char *p = CFDataGetBytePtr(certdata);
            signCert = d2i_X509(0, &p, CFDataGetLength(certdata));
            CFRelease(certdata);
            if(!signCert)
                THROW_OPENSSLEXCEPTION("Failed to parse PKCS12 certificate");

            CFDataRef keydata = nullptr;
            SecKeyImportExportParameters params;
            memset( &params, 0, sizeof(params) );
            params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
            params.passphrase = CFSTR("pass");
            SecKeychainItemExport(keyref, kSecFormatWrappedPKCS8, 0, &params, &keydata);
            CFRelease(keyref);
            if(!keydata)
                THROW("Failed to read PKCS12 key");
            BIO *bio = BIO_new_mem_buf((void*)CFDataGetBytePtr(keydata), CFDataGetLength(keydata));
            signKey = d2i_PKCS8PrivateKey_bio(bio, 0, [](char *buf, int bufsiz, int, void *) -> int {
                static const char password[] = "pass";
                int res = strlen(password);
                if (res > bufsiz)
                        res = bufsiz;
                memcpy(buf, password, res);
                return res;
            }, 0);
            CFRelease(keydata);
            BIO_free(bio);

            if(!signKey)
                THROW_OPENSSLEXCEPTION("Failed to parse PKCS12 key");
        } else {
#endif
        BIO *bio = BIO_new_file(c->PKCS12Cert().c_str(), "rb");
        if(!bio)
            THROW_OPENSSLEXCEPTION("Failed to open PKCS12 certificate: %s.", c->PKCS12Cert().c_str());
        SCOPE(PKCS12, p12, d2i_PKCS12_bio(bio, 0));
        BIO_free(bio);
        if(!p12)
            THROW_OPENSSLEXCEPTION("Failed to read PKCS12 certificate: %s.", c->PKCS12Cert().c_str());

        int res = PKCS12_parse(p12.get(), c->PKCS12Pass().c_str(), &signKey, &signCert, 0);
        if(!res)
            THROW_OPENSSLEXCEPTION("Failed to parse PKCS12 certificate.");
        else // Hack: clear PKCS12_parse error ERROR: 185073780 - error:0B080074:x509 certificate routines:X509_check_private_key:key values mismatch
            OpenSSLException();
#ifdef USE_KEYCHAIN
        }
#endif
        if(!OCSP_request_sign(req.get(), signCert, signKey, EVP_sha1(), 0, 0))
            THROW_OPENSSLEXCEPTION("Failed to sign OCSP request.");
        X509_free(signCert);
        EVP_PKEY_free(signKey);
    }

    return req.release();
}

X509Cert OCSP::responderCert() const
{
    if(!basic)
        return X509Cert();
    for(int i = 0; i < sk_X509_num(basic->certs); ++i)
    {
        X509Cert cert(sk_X509_value(basic->certs, i));
        if(compareResponderCert(cert))
            return cert;
    }
    for(const X509Cert &cert: X509CertStore::instance()->certs())
    {
        if(compareResponderCert(cert))
            return cert;
    }
    return X509Cert();
}

/**
 * Sends OCSP request to the server and returns the response got from the server.
 *
 * @param req OCSP request to be sent to the OCSP server.
 * @return returns OCSP response.
 * @throws IOException throws exception if the server failed to accept request or
 *         returned incorrectly formated OCSP response.
 */
OCSP_RESPONSE* OCSP::sendRequest(const string &_url, OCSP_REQUEST *req, const string &useragent)
{
    char *host = nullptr, *port = nullptr, *path = nullptr;
    int ssl = 0;
    if(!OCSP_parse_url(const_cast<char*>(_url.c_str()), &host, &port, &path, &ssl))
        THROW_OPENSSLEXCEPTION("Incorrect OCSP URL provided: '%s'.", _url.c_str());

    string hostname = host ? host : "";
    if(port)
        hostname += ":" + string(port);
    string url = strlen(path) == 1 && path[0] == '/' && _url[_url.size() - 1] != '/' ? _url + "/" : _url;
    OPENSSL_free(host);
    OPENSSL_free(port);
    OPENSSL_free(path);

    string chostname = hostname;
    Conf *c = Conf::instance();
    if(!c->proxyHost().empty())
    {
        chostname = c->proxyHost();
        if(!c->proxyPort().empty())
            chostname += ":" + c->proxyPort();
    }

    SCOPE2(BIO, connection, BIO_new_connect(const_cast<char*>(chostname.c_str())), BIO_free_all);
    if(!connection)
        THROW_OPENSSLEXCEPTION("Failed to create connection with host: '%s'", chostname.c_str());

    SCOPE(SSL_CTX, ctx, nullptr);
    if(ssl > 0)
    {
        ctx.reset(SSL_CTX_new(SSLv23_client_method()));
        if(!ctx)
            THROW_OPENSSLEXCEPTION("Failed to create connection with host: '%s'", chostname.c_str());
        SSL_CTX_set_mode(ctx.get(), SSL_MODE_AUTO_RETRY);
        BIO *sconnection = BIO_new_ssl(ctx.get(), 1);
        if(!sconnection)
            THROW_OPENSSLEXCEPTION("Failed to create ssl connection with host: '%s'", chostname.c_str());
        connection.reset(BIO_push(sconnection, connection.release()));
    }

    if(!BIO_do_connect(connection.get()))
        THROW_OPENSSLEXCEPTION("Failed to connect to host: '%s'", chostname.c_str());

    string auth;
    if(!c->proxyUser().empty() || !c->proxyPass().empty())
    {
        BIO *b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        SCOPE2(BIO, hash, BIO_push(b64, BIO_new(BIO_s_mem())), BIO_free_all);
        BIO_printf(hash.get(), "%s:%s", c->proxyUser().c_str(), c->proxyPass().c_str());
        (void)BIO_flush(hash.get());
        char *base64 = nullptr;
        BIO_get_mem_data(hash.get(), &base64);
        auth.append("Basic ");
        auth.append(base64);
    }

    string user_agent;
    user_agent += "LIB libdigidocpp/";
    user_agent += VER_STR(MAJOR_VER.MINOR_VER.RELEASE_VER.BUILD_VER);
    user_agent += " APP " + appInfo() + " " + useragent;

    OCSP_RESPONSE* resp = nullptr;
#if OPENSSL_VERSION_NUMBER > 0x10000000
    SCOPE(OCSP_REQ_CTX, rctx, OCSP_sendreq_new(connection.get(), const_cast<char*>(url.c_str()), 0, -1));
    if(!rctx)
        THROW_OPENSSLEXCEPTION("Failed to set OCSP request headers.");
    if(!OCSP_REQ_CTX_add1_header(rctx.get(), "Host", const_cast<char*>(hostname.c_str())))
        THROW_OPENSSLEXCEPTION("Failed to set OCSP request headers.");
    if(!auth.empty() && !OCSP_REQ_CTX_add1_header(rctx.get(), "Proxy-Authorization", const_cast<char*>(auth.c_str())))
        THROW_OPENSSLEXCEPTION("Failed to set OCSP request headers.");
    if(!OCSP_REQ_CTX_add1_header(rctx.get(), "User-Agent", user_agent.c_str()))
        THROW_OPENSSLEXCEPTION("Failed to set OCSP request headers.");
    if(!OCSP_REQ_CTX_set1_req(rctx.get(), req))
        THROW_OPENSSLEXCEPTION("Failed to set OCSP request headers.");
    if(!OCSP_sendreq_nbio(&resp, rctx.get()))
        THROW_OPENSSLEXCEPTION("Failed to send OCSP request.");
#else
    // HACK to alter openssl OCSP request http header
    string header;
    header += url + " HTTP/1.0\r\n";
    header += "Host: " + hostname += "\r\n";
    if(!auth.empty())
        header += "Proxy-Authorization: " + auth + "\r\n";
    header += "User-Agent: " + user_agent + "\r\n";
    header += "X-Ignore:"; // needed for disabling OCSP_sendreq_bio "HTTP/1.0" headers
    resp = OCSP_sendreq_bio(connection.get(), const_cast<char*>(header.c_str()), req);
#endif

    if(!resp)
        THROW_OPENSSLEXCEPTION("Failed to send OCSP request.");
    return resp;
}

vector<unsigned char> OCSP::toDer() const
{
    vector<unsigned char> result;
    if(!resp)
        return result;
    int size = i2d_OCSP_RESPONSE(resp.get(), 0);
    if(size < 0)
        return result;
    result.resize(size_t(size));
    unsigned char *p = result.data();
    if(i2d_OCSP_RESPONSE(resp.get(), &p) < 0)
        result.clear();
    return result;
}

/**
 * Check that response was signed with trusted OCSP certificate
 */
void OCSP::verifyResponse(const X509Cert &cert) const
{
    if(!resp)
        THROW("Failed to verify OCSP response.");
    time_t t = util::date::ASN1TimeToTime_t(producedAt());
    SCOPE(X509_STORE, store, X509CertStore::createStore(&t));
    //OCSP_TRUSTOTHER - enables OCSP_NOVERIFY
    //OCSP_NOSIGS - does not verify ocsp signatures
    //OCSP_NOVERIFY - ignores signer(responder) cert verification, requires store otherwise crashes
    //OCSP_NOCHECKS - cancel futurer responder issuer checks and trust bits
    //OCSP_NOEXPLICIT - returns 0 by mistake
    //all checks enabled fails trust bit check, cant use OCSP_NOEXPLICIT instead using OCSP_NOCHECKS
    int result = OCSP_basic_verify(basic.get(), nullptr, store.get(), OCSP_NOCHECKS);
    if(result <= 0)
        THROW_OPENSSLEXCEPTION("Failed to verify OCSP response.");

    X509Cert issuer = X509CertStore::instance()->findIssuer(cert);
    if(!issuer)
    {
        Exception e(__FILE__, __LINE__, "Certificate status: unknown");
        e.setCode( Exception::CertificateUnknown );
        throw e;
    }
    for(int i = 0; i < OCSP_resp_count(basic.get()); ++i)
    {
        SCOPE(OCSP_CERTID, certId, OCSP_cert_to_id(0, cert.handle(), issuer.handle()));
        int status = -1; int reason = -1;
        /*result =*/ OCSP_resp_find_status(basic.get(), certId.get(), &status, &reason, 0, 0, 0);
        switch(status)
        {
        case V_OCSP_CERTSTATUS_GOOD: break;
        case V_OCSP_CERTSTATUS_REVOKED:
        {
            DEBUG("OCSP status: REVOKED");
            Exception e(__FILE__, __LINE__, "Certificate status: revoked");
            e.setCode(Exception::CertificateRevoked);
            throw e;
        }
        case V_OCSP_CERTSTATUS_UNKNOWN:
        default:
        {
            DEBUG("OCSP status: UNKNOWN");
            Exception e(__FILE__, __LINE__, "Certificate status: unknown");
            e.setCode( Exception::CertificateUnknown );
            throw e;
        }
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
    X509_EXTENSION *ext = OCSP_BASICRESP_get_ext(basic.get(), resp_idx);
    if(!ext)
        return nonce;

    nonce.assign(ext->value->data, ext->value->data + ext->value->length);
#if 1 //def OCSP_NATIVE_NONCE
    //OpenSSL OCSP created messages NID_id_pkix_OCSP_Nonce field is DER encoded twice, not a problem with java impl
    //XXX: UglyHackTM check if nonceAsn1 contains ASN1_OCTET_STRING
    //XXX: if first 2 bytes seem to be beginning of DER ASN1_OCTET_STRING then remove them
    // We assume that bdoc nonce has always octet string header
    if(nonce.size() > 2 && nonce[0] == V_ASN1_OCTET_STRING && nonce[1] == nonce.size()-2)
        nonce.erase(nonce.begin(), nonce.begin() + 2);
#endif
    return nonce;
}

string OCSP::producedAt() const
{
    string result;
    if(!basic)
        return result;
    ASN1_GENERALIZEDTIME* time = basic->tbsResponseData->producedAt;
    result.assign(time->data, time->data+time->length);
    return result;
}
