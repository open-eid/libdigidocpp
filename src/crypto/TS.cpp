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

#include <openssl/rand.h>
#include <openssl/ts.h>

#include <algorithm>
#include <cstring>

using namespace digidoc;
using namespace std;

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
    nonce->data = (unsigned char*)OPENSSL_malloc(nonce->length + 1);
    RAND_bytes(nonce->data, nonce->length);
    TS_REQ_set_nonce(req.get(), nonce.get());

    int len = i2d_TS_REQ(req.get(), 0);
    vector<unsigned char> data(len, 0);
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
    ctx->flags = TS_VFY_NONCE|TS_VFY_VERSION;
    ctx->nonce = nonce.release();
    if(TS_RESP_verify_response(ctx.get(), resp.get()) != 1)
        THROW_OPENSSLEXCEPTION("Failed to verify TS response.");

    d.reset(resp->token, function<void(PKCS7*)>(PKCS7_free));
    resp->token = nullptr;
}

TS::TS(const std::vector<unsigned char> &data)
{
    if(data.empty())
        return;
    const unsigned char *p = data.data();
    d.reset(d2i_PKCS7(0, &p, long(data.size())), function<void(PKCS7*)>(PKCS7_free));
}

X509Cert TS::cert() const
{
    if(!d || !PKCS7_type_is_signed(d.get()))
        return X509Cert();

    STACK_OF(X509) *signers = PKCS7_get0_signers(d.get(), 0, 0);
    if(!signers || sk_X509_num(signers) != 1)
        return X509Cert();

    X509Cert cert(sk_X509_value(signers, 0));
    sk_X509_free(signers);
    return cert;
}

string TS::digestMethod() const
{
    if(!d)
        return string();
    SCOPE(TS_TST_INFO, info, PKCS7_to_TS_TST_INFO(d.get()));
    switch(OBJ_obj2nid(info->msg_imprint->hash_algo->algorithm))
    {
    case NID_sha1: return URI_SHA1;
    case NID_sha224: return URI_SHA224;
    case NID_sha256: return URI_SHA256;
    case NID_sha384: return URI_SHA384;
    case NID_sha512: return URI_SHA512;
    default: return "";
    }
}

string TS::time() const
{
    if(!d)
        return string();
    SCOPE(TS_TST_INFO, info, PKCS7_to_TS_TST_INFO(d.get()));
    if(!info)
        return string();
    return string((char*)info->time->data, info->time->length);
}

void TS::verify(const Digest &digest)
{
    if(!d)
        THROW_OPENSSLEXCEPTION("Failed to verify TS response.");

    vector<unsigned char> data = digest.result();
    SCOPE(TS_VERIFY_CTX, ctx, TS_VERIFY_CTX_new());
    ctx->flags = TS_VFY_IMPRINT|TS_VFY_VERSION|TS_VFY_SIGNATURE;
    ctx->imprint = data.data();
    ctx->imprint_len = (unsigned int)data.size();

    ctx->store = X509_STORE_new();
    X509CertStore::instance()->activate(cert().issuerName("C"));
    for(const X509Cert &i: X509CertStore::instance()->certs())
        X509_STORE_add_cert(ctx->store, i.handle());
    OpenSSLException(); // Clear errors

    SCOPE(X509_STORE_CTX, csc, X509_STORE_CTX_new());
    if (!csc)
        THROW_OPENSSLEXCEPTION("Failed to create X509_STORE_CTX");

    if(!X509_STORE_CTX_init(csc.get(), ctx->store, 0, 0))
        THROW_OPENSSLEXCEPTION("Failed to init X509_STORE_CTX");

    X509_STORE_set_verify_cb_func(ctx->store, [](int ok, X509_STORE_CTX *ctx) -> int {
        switch(X509_STORE_CTX_get_error(ctx))
        {
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        case X509_V_ERR_CERT_UNTRUSTED:
        {
            const vector<X509Cert> &list = X509CertStore::instance()->certs();
            if(find(list.begin(), list.end(), X509Cert(ctx->current_cert)) != list.end())
                return 1;
            return ok;
        }
        default: return ok;
        }
    });

    int err = TS_RESP_verify_token(ctx.get(), d.get());
    //Avoid CRYPTO_free
    ctx->imprint = nullptr;
    ctx->imprint_len = 0;
    if(err != 1)
    {
        long err = ERR_get_error();
        if(ERR_GET_LIB(err) == 47 && ERR_GET_REASON(err) == TS_R_CERTIFICATE_VERIFY_ERROR)
        {
            Exception e(EXCEPTION_PARAMS("Certificate status: unknown"));
            e.setCode( Exception::CertificateUnknown );
            throw e;
        }
        THROW_OPENSSLEXCEPTION("Failed to verify TS response.");
    }
}

TS::operator vector<unsigned char>() const
{
    if(!d)
        return vector<unsigned char>();
    vector<unsigned char> der(i2d_PKCS7(d.get(), 0), 0);
    if(der.empty())
        return der;
    unsigned char *p = der.data();
    i2d_PKCS7(d.get(), &p);
    return der;
}
