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

#if OPENSSL_VERSION_NUMBER < 0x10010000L
static void TS_VERIFY_CTX_set_flags(TS_VERIFY_CTX *ctx, int f)
{
    ctx->flags = f;
}

static void TS_VERIFY_CTX_set_imprint(TS_VERIFY_CTX *ctx, unsigned char *hexstr, long len)
{
    ctx->imprint = hexstr;
    ctx->imprint_len = len;
}

static void TS_VERIFY_CTX_set_store(TS_VERIFY_CTX *ctx, X509_STORE *s)
{
    ctx->store = s;
}
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

    int len = i2d_TS_REQ(req.get(), 0);
    vector<unsigned char> data(size_t(len), 0);
    unsigned char *p = data.data();
    i2d_TS_REQ(req.get(), &p);

    string result = Connect(url, "POST", 0, useragent).exec({
        {"Content-Type", "application/timestamp-query"},
        {"Accept", "application/timestamp-reply"},
        {"Connection", "Close"},
        {"Cache-Control", "no-cache"}
    }, data).content;

    const unsigned char *p2 = (const unsigned char*)result.c_str();
    SCOPE(TS_RESP, resp, d2i_TS_RESP(0, &p2, long(result.size())));
    if(!resp)
        THROW_OPENSSLEXCEPTION("Failed to parse TS response.");

    SCOPE(TS_VERIFY_CTX, ctx, TS_VERIFY_CTX_new());
    TS_VERIFY_CTX_set_flags(ctx.get(), TS_VFY_VERSION);//|TS_VFY_NONCE);
    //ctx->nonce = nonce.release();
    if(TS_RESP_verify_response(ctx.get(), resp.get()) != 1)
        THROW_OPENSSLEXCEPTION("Failed to verify TS response.");

    d.reset(PKCS7_dup(TS_RESP_get_token(resp.get())), function<void(PKCS7*)>(PKCS7_free));
}

TS::TS(const std::vector<unsigned char> &data)
{
    if(data.empty())
        return;
    const unsigned char *p = data.data();
    d.reset(d2i_PKCS7(0, &p, long(data.size())), function<void(PKCS7*)>(PKCS7_free));
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
    SCOPE2(BIO, bio, BIO_new_mem_buf((void*)data.data(), int(data.size())), BIO_free_all);
    cms.reset(d2i_CMS_bio(bio.get(), NULL), CMS_ContentInfo_free);
    if(!cms || OBJ_obj2nid(CMS_get0_eContentType(cms.get())) != NID_id_smime_ct_TSTInfo)
        cms.reset();
#endif
}

X509Cert TS::cert() const
{
    STACK_OF(X509) *signers = [&]() -> STACK_OF(X509)* {
        if(d && PKCS7_type_is_signed(d.get()))
            return PKCS7_get0_signers(d.get(), 0, 0);
#ifndef OPENSSL_NO_CMS
        else if(cms)
            return CMS_get1_certs(cms.get());
#endif
        else
            return nullptr;
    }();

    if(!signers || sk_X509_num(signers) != 1)
        return X509Cert();

    X509Cert cert(sk_X509_value(signers, 0));
    sk_X509_free(signers);
    return cert;
}

string TS::digestMethod() const
{
    SCOPE(TS_TST_INFO, info, tstInfo());
    if(!info)
        return string();
    X509_ALGOR *algo = TS_MSG_IMPRINT_get_algo(TS_TST_INFO_get_msg_imprint(info.get()));
    switch(OBJ_obj2nid(algo->algorithm))
    {
    case NID_sha1: return URI_SHA1;
    case NID_sha224: return URI_SHA224;
    case NID_sha256: return URI_SHA256;
    case NID_sha384: return URI_SHA384;
    case NID_sha512: return URI_SHA512;
    default: return "";
    }
}

string TS::serial() const
{
    SCOPE(TS_TST_INFO, info, tstInfo());

    if (info)
    {
        string serial;
        SCOPE2(BIGNUM, bn, ASN1_INTEGER_to_BN(TS_TST_INFO_get_serial(info.get()), 0), BN_free);
        if(!!bn)
        {
            char *str = BN_bn2dec(bn.get());
            if(str)
                serial = str;
            OPENSSL_free(str);
        }

        return serial;
    }

    return string();
}

string TS::time() const
{
    SCOPE(TS_TST_INFO, info, tstInfo());
    const ASN1_GENERALIZEDTIME *time = TS_TST_INFO_get_time(info.get());
    return info ? string((char*)time->data, size_t(time->length)) : string();
}

TS_TST_INFO* TS::tstInfo() const
{
    if(d)
        return PKCS7_to_TS_TST_INFO(d.get());
#ifndef OPENSSL_NO_CMS
    else if(cms)
    {
        BIO *out = CMS_dataInit(cms.get(), NULL);
        TS_TST_INFO *info =  d2i_TS_TST_INFO_bio(out, NULL);
        BIO_free(out);
        return info;
    }
#endif
    else
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
    if(!X509_STORE_CTX_init(csc.get(), store.get(), 0, 0))
        THROW_OPENSSLEXCEPTION("Failed to init X509_STORE_CTX");

    if(d)
    {
        SCOPE(TS_VERIFY_CTX, ctx, TS_VERIFY_CTX_new());
        TS_VERIFY_CTX_set_flags(ctx.get(), TS_VFY_IMPRINT|TS_VFY_VERSION|TS_VFY_SIGNATURE);
        TS_VERIFY_CTX_set_imprint(ctx.get(), data.data(), (long)data.size());
        TS_VERIFY_CTX_set_store(ctx.get(), store.release());
        int err = TS_RESP_verify_token(ctx.get(), d.get());
        TS_VERIFY_CTX_set_imprint(ctx.get(), nullptr, 0); //Avoid CRYPTO_free
        if(err != 1)
        {
            unsigned long err = ERR_get_error();
            if(ERR_GET_LIB(err) == 47 && ERR_GET_REASON(err) == TS_R_CERTIFICATE_VERIFY_ERROR)
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
        SCOPE2(BIO, out, BIO_new(BIO_s_mem()), BIO_free_all);
        int err = CMS_verify(cms.get(), NULL, store.get(), NULL, out.get(), 0);
        if(err != 1)
            THROW_OPENSSLEXCEPTION("Failed to verify TS response.");

        SCOPE(TS_TST_INFO, info, d2i_TS_TST_INFO_bio(out.get(), NULL));
        ASN1_OCTET_STRING *msg = TS_MSG_IMPRINT_get_msg(TS_TST_INFO_get_msg_imprint(info.get()));
        if(data.size() != size_t(ASN1_STRING_length(msg)) ||
            memcmp(data.data(), ASN1_STRING_data(msg), data.size()))
            THROW_OPENSSLEXCEPTION("Failed to verify TS response.");
    }
#endif
    else
        THROW_OPENSSLEXCEPTION("Failed to verify TS response.");
}

TS::operator vector<unsigned char>() const
{
    if(d)
    {
        vector<unsigned char> der(i2d_PKCS7(d.get(), 0), 0);
        if(der.empty())
            return der;
        unsigned char *p = der.data();
        i2d_PKCS7(d.get(), &p);
        return der;
    }
#ifndef OPENSSL_NO_CMS
    else if(cms)
    {
        vector<unsigned char> der(i2d_CMS_ContentInfo(cms.get(), 0), 0);
        if(der.empty())
            return der;
        unsigned char *p = der.data();
        i2d_CMS_ContentInfo(cms.get(), &p);
        return der;
    }
#endif
    return vector<unsigned char>();
}
