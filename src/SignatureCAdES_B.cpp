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

#include <SignatureCAdES_B.h>
#include <SignatureCAdES_p.h>

#include <crypto/Digest.h>
#include <crypto/OpenSSLHelpers.h>
#include <crypto/Signer.h>
#include <crypto/X509Cert.h>
#include <crypto/X509CertStore.h>
#include <util/DateTime.h>

#include <openssl/bio.h>
#include <openssl/ts.h>

using namespace digidoc;
using namespace digidoc::util::date;
using namespace std;

SignatureCAdES_B::SignatureCAdES_B(Signer *signer)
    : d(new SignatureCAdESPrivate)
{
    d->reset(CMS_sign(nullptr, nullptr, nullptr, nullptr, CMS_BINARY|CMS_DETACHED|CMS_PARTIAL), CMS_ContentInfo_free);
    d->method = *RSA_get_default_method();
    d->method.name = "PDFSign";
    d->method.rsa_sign = [](int type, const unsigned char *m, unsigned int m_length,
          unsigned char *sigret, unsigned int *siglen, const RSA *rsa) -> int {
        string uri;
        switch(type)
        {
        case NID_sha1:  uri = URI_RSA_SHA1; break;
        case NID_sha224: uri = URI_RSA_SHA224; break;
        case NID_sha256: uri = URI_RSA_SHA256; break;
        case NID_sha384: uri = URI_RSA_SHA384; break;
        case NID_sha512: uri = URI_RSA_SHA512; break;
        default: break;
        }
        Signer *signer = (Signer*)RSA_get_app_data(rsa);
        vector<unsigned char> signature = signer->sign(uri, vector<unsigned char>(m, m + m_length));
        *siglen = signature.size();
        memcpy(sigret, signature.data(), signature.size());
        return 1;
    };

    X509Cert x509 = signer->cert();
    X509 *cert = x509.handle();
    EVP_PKEY *key = X509_get_pubkey(cert);
    RSA *rsa = EVP_PKEY_get1_RSA(key);
    RSA_set_method(rsa, &d->method);
    RSA_set_app_data(rsa, signer);
    rsa->flags |= RSA_FLAG_SIGN_VER;
    EVP_PKEY_set1_RSA(key, rsa);

    d->si = CMS_add1_signer(d->get(), cert, key, nullptr, CMS_BINARY|CMS_DETACHED|CMS_PARTIAL);

    ESS_CERT_ID *cid = ESS_CERT_ID_new();
    ASN1_OCTET_STRING_set(cid->hash, cert->sha1_hash, sizeof(cert->sha1_hash));

    GENERAL_NAME *name = GENERAL_NAME_new();
    name->type = GEN_DIRNAME;
    name->d.dirn = X509_NAME_dup(cert->cert_info->issuer);

    cid->issuer_serial = ESS_ISSUER_SERIAL_new();
    sk_GENERAL_NAME_push(cid->issuer_serial->issuer, name);
    ASN1_INTEGER_free(cid->issuer_serial->serial);
    cid->issuer_serial->serial = ASN1_INTEGER_dup(cert->cert_info->serialNumber);

    ESS_SIGNING_CERT *ess = ESS_SIGNING_CERT_new();
    ess->cert_ids = sk_ESS_CERT_ID_new_null();
    sk_ESS_CERT_ID_push(ess->cert_ids, cid);

    vector<unsigned char> signingCertificate(size_t(i2d_ESS_SIGNING_CERT(ess, nullptr)), 0);
    unsigned char *p = signingCertificate.data();
    i2d_ESS_SIGNING_CERT(ess, &p);
    CMS_signed_add1_attr_by_NID(d->si, NID_id_smime_aa_signingCertificate, V_ASN1_SEQUENCE, signingCertificate.data(), int(signingCertificate.size()));
}

SignatureCAdES_B::SignatureCAdES_B(const vector<unsigned char> &data)
    : d(new SignatureCAdESPrivate)
{
    SCOPE2(BIO, bio, BIO_new_mem_buf(data.data(), int(data.size())), BIO_free_all);
    d->reset(d2i_CMS_bio(bio.get(), NULL), CMS_ContentInfo_free);

    if(!d->get() || OBJ_obj2nid(CMS_get0_eContentType(d->get())) != NID_pkcs7_data)
        THROW("Failed to parse signature");

    STACK_OF(CMS_SignerInfo) *sis = CMS_get0_SignerInfos(d->get());
    if(sk_CMS_SignerInfo_num(sis) != 1)
        THROW("More than 1 signer info");
    d->si = sk_CMS_SignerInfo_value(sis, 0);
}

SignatureCAdES_B::~SignatureCAdES_B()
{
    delete d;
}

string SignatureCAdES_B::claimedSigningTime() const
{
    int pos = CMS_signed_get_attr_by_NID(d->si, NID_pkcs9_signingTime, -1);
    if(pos == -1)
        return string();
    X509_ATTRIBUTE *attr = CMS_signed_get_attr(d->si, pos);
    if(!attr)
        return string();
    ASN1_TYPE *type = X509_ATTRIBUTE_get0_type(attr, 0);
    if(!type || type->type != V_ASN1_UTCTIME)
        return string();
    string time((char*)type->value.utctime->data, type->value.utctime->length);
    return (time.compare(0, 2, "50") <= 0 ? "20" : "19") + time;
}

void SignatureCAdES_B::sign()
{
    vector<unsigned char> bytes = dataToSign();
    SCOPE2(BIO, data, BIO_new_mem_buf(bytes.data(), int(bytes.size())), BIO_free_all);
    if(CMS_final(d->get(), data.get(), nullptr, CMS_BINARY|CMS_DETACHED) != 1)
        THROW("Failed to calculate signature");
}

string SignatureCAdES_B::signatureMethod() const
{
    X509_ALGOR *dig = nullptr;
    CMS_SignerInfo_get0_algs(d->si, nullptr, nullptr, &dig, nullptr);
    switch(OBJ_obj2nid(dig->algorithm))
    {
    case NID_sha1:  return URI_SHA1;
    case NID_sha224: return URI_SHA224;
    case NID_sha256: return URI_SHA256;
    case NID_sha384: return URI_SHA384;
    case NID_sha512: return URI_SHA512;
    default: return string();
    }
}

X509Cert SignatureCAdES_B::signingCertificate() const
{
    STACK_OF(X509) *signers = CMS_get1_certs(d->get());
    if(!signers)
        return X509Cert();
    X509Cert cert(sk_X509_num(signers) >= 1 ? sk_X509_value(signers, 0) : nullptr);
    sk_X509_free(signers);
    return cert;
}

void SignatureCAdES_B::validate() const
{
    validate(POLv2);
}

void SignatureCAdES_B::validate(const string &policy) const
{
    DEBUG("SignatureCAdES_B::validate(%s)", policy.c_str());
    Exception exception(__FILE__, __LINE__, "Signature validation");
    try {
        vector<unsigned char> data = dataToSign();
        SCOPE2(BIO, out, BIO_new_mem_buf(data.data(), int(data.size())), BIO_free_all);
        // CMS_NO_SIGNER_CERT_VERIFY does not play well with expired certificates, will be handled later
        if(CMS_verify(d->get(), nullptr, nullptr, out.get(), nullptr, CMS_NO_SIGNER_CERT_VERIFY) != 1)
            THROW_OPENSSLEXCEPTION("Failed to validate signature.");

        string time = trustedSigningTime();
        if(time.empty())
            THROW("SigningTime missing");
        if(!X509CertStore::instance()->verify(signingCertificate(), policy == POLv1))
            THROW("Unable to verify signing certificate");
    } catch(const Exception &e) {
        exception.addCause(e);
    }
    if(!exception.causes().empty())
        throw exception;
}

SignatureCAdES_B::operator vector<unsigned char>() const
{
    vector<unsigned char> data(size_t(i2d_CMS_ContentInfo(d->get(), nullptr)), 0);
    if(data.empty())
        return data;
    unsigned char *p = data.data();
    i2d_CMS_ContentInfo(d->get(), &p);
    return data;
}
