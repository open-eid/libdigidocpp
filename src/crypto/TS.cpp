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

#include "TS.h"

#include "Conf.h"
#include "Container.h"
#include "Exception.h"
#include "crypto/Connect.h"
#include "crypto/Digest.h"
#include "crypto/OpenSSLHelpers.h"
#include "crypto/X509CertStore.h"
#include "util/DateTime.h"

#ifndef OPENSSL_NO_CMS
#include <openssl/cms.h>
#endif
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/ts.h>

#include <algorithm>

using namespace digidoc;
using namespace std;

#if defined(LIBRESSL_VERSION_NUMBER)
#include <cstring>

void *OPENSSL_memdup(const void *data, size_t size)
{
    void *copy;

    if (data == NULL || size == 0 || size >= INT_MAX)
        return NULL;

    if ((copy = OPENSSL_malloc(size)) == NULL)
        return NULL;

    return memcpy(copy, data, size);
}
#endif
#if OPENSSL_VERSION_NUMBER < 0x30400000L
#define TS_VERIFY_CTX_set0_imprint TS_VERIFY_CTX_set_imprint
#define TS_VERIFY_CTX_set0_store TS_VERIFY_CTX_set_store
#endif

TS::TS(const Digest &digest, const std::string &userAgent)
    : d(nullptr, PKCS7_free)
    , cms(nullptr, CMS_ContentInfo_free)
{
    auto req = make_unique_ptr<TS_REQ_free>(TS_REQ_new());
    TS_REQ_set_version(req.get(), 1);
    TS_REQ_set_cert_req(req.get(), 1);

    auto algo = make_unique_ptr<X509_ALGOR_free>(X509_ALGOR_new());
    X509_ALGOR_set0(algo.get(), OBJ_nid2obj(Digest::toMethod(digest.uri())), V_ASN1_NULL, nullptr);

    auto msg_imprint = make_unique_ptr<TS_MSG_IMPRINT_free>(TS_MSG_IMPRINT_new());
    TS_MSG_IMPRINT_set_algo(msg_imprint.get(), algo.get());
    vector<unsigned char> digestdata = digest.result();
    TS_MSG_IMPRINT_set_msg(msg_imprint.get(), digestdata.data(), int(digestdata.size()));
    TS_REQ_set_msg_imprint(req.get(), msg_imprint.get());

#if 0
    if(!policy.empty())
    {
        auto obj = make_unique_ptr<ASN1_OBJECT_free>(OBJ_txt2obj(policy.c_str(), 0));
        TS_REQ_set_policy_id(req.get(), obj.get());
    }
#endif

    auto nonce = make_unique_ptr<ASN1_INTEGER_free>(ASN1_INTEGER_new());
    ASN1_STRING_set(nonce.get(), nullptr, 20);
    for(nonce->data[0] = 0; nonce->data[0] == 0;) // Make sure that first byte is not 0x00
        RAND_bytes(nonce->data, nonce->length);
    TS_REQ_set_nonce(req.get(), nonce.get());

    Connect::Result result = Connect(CONF(TSUrl), "POST", 0, CONF(TSCerts), userAgent).exec({
        {"Content-Type", "application/timestamp-query"},
        {"Accept", "application/timestamp-reply"},
        {"Connection", "Close"},
        {"Cache-Control", "no-cache"}
    }, i2d<i2d_TS_REQ>(req));

    if(result.isForbidden())
    {
        Exception e(EXCEPTION_PARAMS("Time-stamp service responded - Forbidden"));
        e.setCode(Exception::TSForbidden);
        throw e;
    }
    if(result.isStatusCode("429"))
    {
        Exception e(EXCEPTION_PARAMS("Time-stamp service responded - Too Many Requests"));
        e.setCode(Exception::TSTooManyRequests);
        throw e;
    }
    if(!result)
        THROW("Failed to send Time-stamp request");

    const unsigned char *p2 = (const unsigned char*)result.content.c_str();
    auto resp = make_unique_ptr<TS_RESP_free>(d2i_TS_RESP(nullptr, &p2, long(result.content.size())));
    if(!resp)
        THROW_OPENSSLEXCEPTION("Failed to parse TS response.");

    auto ctx = make_unique_ptr<TS_VERIFY_CTX_free>(TS_REQ_to_TS_VERIFY_CTX(req.get(), nullptr));
    TS_VERIFY_CTX_set_flags(ctx.get(), TS_VFY_VERSION|TS_VFY_NONCE);
    if(TS_RESP_verify_response(ctx.get(), resp.get()) != 1)
        THROW_OPENSSLEXCEPTION("Failed to verify TS response.");

    d.reset(PKCS7_dup(TS_RESP_get_token(resp.get())));
    DEBUG("TSA time %s", util::date::to_string(time()).c_str());
}

TS::TS(const unsigned char *data, size_t size)
    : d(nullptr, PKCS7_free)
    , cms(nullptr, [](CMS_ContentInfo *contentInfo) {
        CMS_ContentInfo_free(contentInfo);
        ERR_clear_error();
    })
{
    if(size == 0)
        return;
    d.reset(d2i_PKCS7(nullptr, &data, long(size)));
#ifndef OPENSSL_NO_CMS
    if(d)
        return;
    ERR_clear_error();
    /**
     * Handle CMS based TimeStamp tokens
     * https://rt.openssl.org/Ticket/Display.html?id=4519
     * https://github.com/openssl/openssl/issues/993
     *
     * If PKCS7 wrapped TimeStamp parsing fails, try with CMS wrapping
     */
    cms.reset(d2i_CMS_ContentInfo(nullptr, &data, long(size)));
    if(!cms || OBJ_obj2nid(CMS_get0_eContentType(cms.get())) != NID_id_smime_ct_TSTInfo)
        cms.reset();

    ERR_clear_error();
#endif
}

X509Cert TS::cert() const
{
    unique_free_t<STACK_OF(X509)> signers(nullptr, nullptr);
    if(d && PKCS7_type_is_signed(d.get()))
        signers = {PKCS7_get0_signers(d.get(), nullptr, 0),
            [](STACK_OF(X509) *stack) { sk_X509_free(stack); }};
#ifndef OPENSSL_NO_CMS
    if(!signers && cms)
        signers = {CMS_get1_certs(cms.get()),
            [](STACK_OF(X509) *stack) { sk_X509_pop_free(stack, X509_free); }};
#endif
    if(signers && sk_X509_num(signers.get()) == 1)
        return X509Cert(sk_X509_value(signers.get(), 0));
    return X509Cert();
}

auto TS::tstInfo() const
{
    if(d)
        return make_unique_ptr<TS_TST_INFO_free>(PKCS7_to_TS_TST_INFO(d.get()));
#ifndef OPENSSL_NO_CMS
    if(cms)
    {
        if(auto out = make_unique_ptr<BIO_free>(CMS_dataInit(cms.get(), nullptr)))
            return make_unique_ptr<TS_TST_INFO_free>(d2i_TS_TST_INFO_bio(out.get(), nullptr));
    }
#endif
    return make_unique_ptr<TS_TST_INFO_free>(nullptr);
}

string TS::digestMethod() const
{
    auto info = tstInfo();
    if(!info)
        return {};
    if(X509_ALGOR *algo = TS_MSG_IMPRINT_get_algo(TS_TST_INFO_get_msg_imprint(info.get())))
        return Digest::toUri(OBJ_obj2nid(algo->algorithm));
    return {};
}

vector<unsigned char> TS::digestValue() const
{
    if(auto info = tstInfo())
        return i2d<i2d_ASN1_OCTET_STRING>(TS_MSG_IMPRINT_get_msg(TS_TST_INFO_get_msg_imprint(info.get())));
    return {};
}

vector<unsigned char> TS::messageImprint() const
{
    if(auto info = tstInfo())
        return i2d<i2d_TS_MSG_IMPRINT>(TS_TST_INFO_get_msg_imprint(info.get()));
    return {};
}

string TS::serial() const
{
    auto info = tstInfo();
    if(!info)
        return {};

    if(auto bn = make_unique_ptr<BN_free>(ASN1_INTEGER_to_BN(TS_TST_INFO_get_serial(info.get()), nullptr)))
    {
        if(auto str = make_unique_ptr(BN_bn2dec(bn.get()), [](char *data) { OPENSSL_free(data); }))
            return str.get();
    }
    return {};
}

tm TS::time() const
{
    tm tm {};
    if(auto info = tstInfo())
        ASN1_TIME_to_tm(TS_TST_INFO_get_time(info.get()), &tm);
    return tm;
}

void TS::verify(const vector<unsigned char> &digest)
{
    tm tm = time();
    auto store = X509CertStore::createStore(X509CertStore::TSA, tm);
    X509CertStore::instance()->activate(cert());
    if(d)
    {
        auto ctx = make_unique_ptr<TS_VERIFY_CTX_free>(TS_VERIFY_CTX_new());
        TS_VERIFY_CTX_set_flags(ctx.get(), TS_VFY_IMPRINT|TS_VFY_VERSION|TS_VFY_SIGNATURE);
        TS_VERIFY_CTX_set0_imprint(ctx.get(),
            (unsigned char*)OPENSSL_memdup(digest.data(), digest.size()), long(digest.size()));
        TS_VERIFY_CTX_set0_store(ctx.get(), store.release());
        if(TS_RESP_verify_token(ctx.get(), d.get()) != 1)
        {
            unsigned long err = ERR_get_error();
            if(ERR_GET_LIB(err) == ERR_LIB_TS && ERR_GET_REASON(err) == TS_R_CERTIFICATE_VERIFY_ERROR)
            {
                OpenSSLException e(EXCEPTION_PARAMS("Certificate status: unknown"), err);
                e.setCode( Exception::CertificateUnknown );
                throw e;
            }
            throw OpenSSLException(EXCEPTION_PARAMS("Failed to verify TS response."), err);
        }
    }
#ifndef OPENSSL_NO_CMS
    else if(cms)
    {
        auto out = make_unique_ptr<BIO_free>(BIO_new(BIO_s_mem()));
        // Override smime_sign purpose bit because it is actually timestamp
        X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new();
        X509_VERIFY_PARAM_set1_name(param, "smime_sign");
        X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_TIMESTAMP_SIGN);
        X509_VERIFY_PARAM_add0_table(param);
        int err = CMS_verify(cms.get(), nullptr, store.get(), nullptr, out.get(), 0);
        X509_VERIFY_PARAM_table_cleanup();
        if(err != 1)
            THROW_OPENSSLEXCEPTION("Failed to verify TS response.");

        auto info = make_unique_ptr<TS_TST_INFO_free>(d2i_TS_TST_INFO_bio(out.get(), nullptr));
        if(ASN1_OCTET_STRING *msg = TS_MSG_IMPRINT_get_msg(TS_TST_INFO_get_msg_imprint(info.get()));
            std::equal(digest.cbegin(), digest.cend(),
                ASN1_STRING_get0_data(msg), std::next(ASN1_STRING_get0_data(msg), ASN1_STRING_length(msg))))
            THROW_OPENSSLEXCEPTION("Failed to verify TS response.");
    }
#endif
    else
        THROW_OPENSSLEXCEPTION("Failed to verify TS response.");
}

TS::operator vector<unsigned char>() const
{
#ifndef OPENSSL_NO_CMS
    if(cms)
        return i2d<i2d_CMS_ContentInfo>(cms);
#endif
    return i2d<i2d_PKCS7>(d);
}
