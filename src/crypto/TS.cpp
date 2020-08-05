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
#include <cstring>

using namespace digidoc;
using namespace std;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static void TS_VERIFY_CTX_set_flags(TS_VERIFY_CTX *ctx, int f)
{
    ctx->flags = unsigned(f);
}

static void TS_VERIFY_CTX_set_imprint(TS_VERIFY_CTX *ctx, unsigned char *hexstr, long len)
{
    ctx->imprint = hexstr;
    ctx->imprint_len = unsigned(len);
}

static void TS_VERIFY_CTX_set_store(TS_VERIFY_CTX *ctx, X509_STORE *s)
{
    ctx->store = s;
}

#define ASN1_STRING_get0_data ASN1_STRING_data
#endif

TS::TS(const string &url, const Digest &digest, const string &useragent)
{
    SCOPE(TS_REQ, req, TS_REQ_new());
    TS_REQ_set_version(req.get(), 1);
    TS_REQ_set_cert_req(req.get(), 1);

    SCOPE(X509_ALGOR, algo, X509_ALGOR_new());
    algo->algorithm = OBJ_nid2obj(Digest::toMethod(digest.uri()));
    algo->parameter = ASN1_TYPE_new();
    algo->parameter->type = V_ASN1_NULL;

    SCOPE(TS_MSG_IMPRINT, msg_imprint, TS_MSG_IMPRINT_new());
    TS_MSG_IMPRINT_set_algo(msg_imprint.get(), algo.get());
    vector<unsigned char> digestdata = digest.result();
    TS_MSG_IMPRINT_set_msg(msg_imprint.get(), digestdata.data(), int(digestdata.size()));
    TS_REQ_set_msg_imprint(req.get(), msg_imprint.get());

#if 0
    if(!policy.empty())
    {
        SCOPE(ASN1_OBJECT, obj, OBJ_txt2obj(policy.c_str(), 0));
        TS_REQ_set_policy_id(req.get(), obj.get());
    }
#endif

    SCOPE(ASN1_INTEGER, nonce, ASN1_INTEGER_new());
    nonce->length = 20;
    nonce->data = (unsigned char*)OPENSSL_malloc(nonce->length);
    nonce->data[0] = 0;
    while(nonce->data[0] == 0) // Make sure that first byte is not 0x00
        RAND_bytes(nonce->data, nonce->length);
    TS_REQ_set_nonce(req.get(), nonce.get());

    Connect::Result result = Connect(url, "POST", 0, useragent).exec({
        {"Content-Type", "application/timestamp-query"},
        {"Accept", "application/timestamp-reply"},
        {"Connection", "Close"},
        {"Cache-Control", "no-cache"}
    }, i2d(req.get(), i2d_TS_REQ));

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
    SCOPE(TS_RESP, resp, d2i_TS_RESP(nullptr, &p2, long(result.content.size())));
    if(!resp)
        THROW_OPENSSLEXCEPTION("Failed to parse TS response.");

    SCOPE(TS_VERIFY_CTX, ctx, TS_REQ_to_TS_VERIFY_CTX(req.get(), nullptr));
    TS_VERIFY_CTX_set_flags(ctx.get(), TS_VFY_VERSION|TS_VFY_NONCE);
    if(TS_RESP_verify_response(ctx.get(), resp.get()) != 1)
        THROW_OPENSSLEXCEPTION("Failed to verify TS response.");

    d.reset(PKCS7_dup(TS_RESP_get_token(resp.get())), PKCS7_free);
    DEBUG("TSA time %s", time().c_str());
}

TS::TS(const unsigned char *data, size_t size)
{
    if(size == 0)
        return;
    d.reset(d2i_PKCS7(nullptr, &data, long(size)), PKCS7_free);
#ifndef OPENSSL_NO_CMS
    if(d)
        return;
    /**
     * Handle CMS based TimeStamp tokens
     * https://rt.openssl.org/Ticket/Display.html?id=4519
     * https://github.com/openssl/openssl/issues/993
     *
     * If PKCS7 wrapped TimeStamp parsing fails, try with CMS wrapping
     */
    SCOPE(BIO, bio, BIO_new_mem_buf((void*)data, int(size)));
    cms.reset(d2i_CMS_bio(bio.get(), nullptr), CMS_ContentInfo_free);
    if(!cms || OBJ_obj2nid(CMS_get0_eContentType(cms.get())) != NID_id_smime_ct_TSTInfo)
        cms.reset();
#endif
}

X509Cert TS::cert() const
{
    using sk_X509_free_t = void (*)(STACK_OF(X509) *);
    unique_ptr<STACK_OF(X509), sk_X509_free_t> signers = [&] {
        if(d && PKCS7_type_is_signed(d.get()))
            return unique_ptr<STACK_OF(X509), sk_X509_free_t>(PKCS7_get0_signers(d.get(), nullptr, 0),
                [](STACK_OF(X509) *stack) { sk_X509_free(stack); });
#ifndef OPENSSL_NO_CMS
        if(cms)
            return unique_ptr<STACK_OF(X509), sk_X509_free_t>(CMS_get1_certs(cms.get()),
                [](STACK_OF(X509) *stack) { sk_X509_pop_free(stack, X509_free); });
#endif
        return unique_ptr<STACK_OF(X509), sk_X509_free_t>(nullptr, nullptr);
    }();

    if(!signers || sk_X509_num(signers.get()) != 1)
        return X509Cert();
    return X509Cert(sk_X509_value(signers.get(), 0));
}

string TS::digestMethod() const
{
    SCOPE(TS_TST_INFO, info, tstInfo());
    if(!info)
        return {};
    X509_ALGOR *algo = TS_MSG_IMPRINT_get_algo(TS_TST_INFO_get_msg_imprint(info.get()));
    return Digest::toUri(OBJ_obj2nid(algo->algorithm));
}

vector<unsigned char> TS::digestValue() const
{
    SCOPE(TS_TST_INFO, info, tstInfo());
    if(!info)
        return {};
    return i2d(TS_MSG_IMPRINT_get_msg(TS_TST_INFO_get_msg_imprint(info.get())), i2d_ASN1_OCTET_STRING);
}

vector<unsigned char> TS::messageImprint() const
{
    SCOPE(TS_TST_INFO, info, tstInfo());
    if(!info)
        return {};
    return i2d(TS_TST_INFO_get_msg_imprint(info.get()), i2d_TS_MSG_IMPRINT);
}

string TS::serial() const
{
    SCOPE(TS_TST_INFO, info, tstInfo());
    string serial;
    if(!info)
        return serial;

    SCOPE2(BIGNUM, bn, ASN1_INTEGER_to_BN(TS_TST_INFO_get_serial(info.get()), nullptr), BN_free);
    if(bn)
    {
        char *str = BN_bn2dec(bn.get());
        if(str)
            serial = str;
        OPENSSL_free(str);
    }
    return serial;
}

string TS::time() const
{
    SCOPE(TS_TST_INFO, info, tstInfo());
    string result;
    if(!info)
        return result;
    const ASN1_GENERALIZEDTIME *time = TS_TST_INFO_get_time(info.get());
    if(time)
        result.assign((char*)time->data, size_t(time->length));
    return result;
}

TS_TST_INFO* TS::tstInfo() const
{
    if(d)
        return PKCS7_to_TS_TST_INFO(d.get());
#ifndef OPENSSL_NO_CMS
    if(cms)
    {
        SCOPE(BIO, out, CMS_dataInit(cms.get(), nullptr));
        return d2i_TS_TST_INFO_bio(out.get(), nullptr);
    }
#endif
    return nullptr;
}

void TS::verify(const Digest &digest)
{
    vector<unsigned char> data = digest.result();

    time_t t = util::date::ASN1TimeToTime_t(time());
    SCOPE(X509_STORE, store, X509CertStore::createStore(X509CertStore::TSA, &t));
    X509CertStore::instance()->activate(cert().issuerName("C"));
    SCOPE(X509_STORE_CTX, csc, X509_STORE_CTX_new());
    if (!csc)
        THROW_OPENSSLEXCEPTION("Failed to create X509_STORE_CTX");
    if(!X509_STORE_CTX_init(csc.get(), store.get(), nullptr, nullptr))
        THROW_OPENSSLEXCEPTION("Failed to init X509_STORE_CTX");

    if(d)
    {
        SCOPE(TS_VERIFY_CTX, ctx, TS_VERIFY_CTX_new());
        TS_VERIFY_CTX_set_flags(ctx.get(), TS_VFY_IMPRINT|TS_VFY_VERSION|TS_VFY_SIGNATURE);
        TS_VERIFY_CTX_set_imprint(ctx.get(), data.data(), long(data.size()));
        TS_VERIFY_CTX_set_store(ctx.get(), store.release());
        int err = TS_RESP_verify_token(ctx.get(), d.get());
        TS_VERIFY_CTX_set_imprint(ctx.get(), nullptr, 0); //Avoid CRYPTO_free
        if(err != 1)
        {
            unsigned long err = ERR_get_error();
            if(ERR_GET_LIB(err) == ERR_LIB_TS && ERR_GET_REASON(err) == TS_R_CERTIFICATE_VERIFY_ERROR)
            {
                Exception e(EXCEPTION_PARAMS("Certificate status: unknown"));
                e.setCode( Exception::CertificateUnknown );
                throw e;
            }
            THROW_OPENSSLEXCEPTION("Failed to verify TS response.");
        }
    }
#ifndef OPENSSL_NO_CMS
    else if(cms)
    {
        SCOPE(BIO, out, BIO_new(BIO_s_mem()));
        // Override smime_sign purpose bit because it is actually timestamp
        X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new();
        X509_VERIFY_PARAM_set1_name(param, "smime_sign");
        X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_TIMESTAMP_SIGN);
        X509_VERIFY_PARAM_add0_table(param);
        int err = CMS_verify(cms.get(), nullptr, store.get(), nullptr, out.get(), 0);
        X509_VERIFY_PARAM_table_cleanup();
        if(err != 1)
            THROW_OPENSSLEXCEPTION("Failed to verify TS response.");

        SCOPE(TS_TST_INFO, info, d2i_TS_TST_INFO_bio(out.get(), nullptr));
        ASN1_OCTET_STRING *msg = TS_MSG_IMPRINT_get_msg(TS_TST_INFO_get_msg_imprint(info.get()));
        if(data.size() != size_t(ASN1_STRING_length(msg)) ||
            memcmp(data.data(), ASN1_STRING_get0_data(msg), data.size()) != 0)
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
        return i2d(cms.get(), i2d_CMS_ContentInfo);
#endif
    return i2d(d.get(), i2d_PKCS7);
}
