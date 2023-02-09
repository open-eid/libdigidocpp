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

#include "X509Crypto.h"

#include "crypto/Digest.h"
#include "crypto/OpenSSLHelpers.h"
#include "util/File.h"
#include "util/log.h"

#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/ts.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <iterator>

using namespace digidoc;
using namespace std;

/*-
 * IssuerSerial ::= SEQUENCE {
 *         issuer                   GeneralNames,
 *         serialNumber             CertificateSerialNumber
 *         }
 */
using ESS_ISSUER_SERIAL = struct ESS_issuer_serial {
    GENERAL_NAMES *issuer;
    ASN1_INTEGER *serial;
};

/**
 * Initialize RSA crypter.
 *
 * @param cert X.509 certificate.
 */
X509Crypto::X509Crypto(X509Cert cert)
 : cert(move(cert))
{
}

bool X509Crypto::compareIssuerToDer(const vector<unsigned char> &data) const
{
    // DER-encoded instance of type IssuerSerial type defined in IETF RFC 5035 [17].
    const unsigned char *p = data.data();
    SCOPE(ESS_ISSUER_SERIAL, is, d2i_ESS_ISSUER_SERIAL(nullptr, &p, long(data.size())));
    if(!is || sk_GENERAL_NAME_num(is->issuer) != 1)
        return false;

    GENERAL_NAME *issuer = sk_GENERAL_NAME_value(is->issuer, 0);
    return issuer->type == GEN_DIRNAME &&
        X509_NAME_cmp(issuer->d.dirn, X509_get_issuer_name(cert.handle())) == 0 &&
        ASN1_INTEGER_cmp(is->serial, X509_get_serialNumber(cert.handle())) == 0;
}

/**
 * Check if X509Cert issuer is same as provided issuer name by
 * http://www.w3.org/TR/xmldsig-core/#dname-encrules which refers to
 * http://www.ietf.org/rfc/rfc4514.txt
 *
 * String X.500 AttributeType
 * CN commonName (2.5.4.3)
 * L localityName (2.5.4.7)
 * ST stateOrProvinceName (2.5.4.8)
 * O organizationName (2.5.4.10)
 * OU organizationalUnitName (2.5.4.11)
 * C countryName (2.5.4.6)
 * STREET streetAddress (2.5.4.9)
 * DC domainComponent (0.9.2342.19200300.100.1.25)
 * UID userId (0.9.2342.19200300.100.1.1)
 *
 * These attribute types are described in [RFC4519].
 * Implementations MAY recognize other DN string representations.
 * However, as there is no requirement that alternative DN string
 * representations be recognized (and, if so, how), implementations
 * SHOULD only generate DN strings in accordance with Section 2 of this document.
 *
 * @param issuer name
 * @return 0 if equal, otherwise a number different from 0 is returned
 * @throw IOException if error
 */
int X509Crypto::compareIssuerToString(const string &name) const
{
    static const array list {
        "CN", "commonName",
        "L", "localityName",
        "ST", "stateOrProvinceName",
        "O", "organizationName",
        "OU", "organizationalUnitName",
        "C", "countryName",
        "STREET", "streetAddress",
        "DC", "domainComponent",
        "UID", "userId"
    };

    for(size_t old = 0, pos = 0; ; )
    {
        pos = name.find(',', old);
        if(pos == string::npos)
        {
            pos = name.size();
            if(pos < old)
                break;
        }
        else
        {
            if(name[pos-1] == '\\')
            {
                old = pos;
                continue;
            }
        }

        string nameitem = name.substr(old, pos - old);
        old = pos + 1;

        if((pos = nameitem.find('=')) == string::npos ||
            nameitem.compare(pos-1, 1, "\\") == 0)
            continue;

        string obj = nameitem.substr(0, pos);
        if(find(list.cbegin(), list.cend(), obj) == list.cend())
            continue;

        ASN1_OBJECT *obja = OBJ_txt2obj(obj.c_str(), 0);
        string tmp = nameitem.substr(pos+1, pos-old);

        string value;
        char data[] = "00";
        static const string escape = " #+,;<=>\\";
        for(string::const_iterator i = tmp.cbegin(); i != tmp.cend(); ++i)
        {
            if(*i == '\\' && distance(i, tmp.cend()) > 2 && isxdigit(*(i+1)) && isxdigit(*(i+2)))
            {
                data[0] = *(++i);
                data[1] = *(++i);
                value += static_cast<char>(strtoul(data, nullptr, 16));
            }
            else if(*i == '\\' && escape.find(*(i+1)) == string::npos)
                value += *(++i);
            else
                value += *i;
        }

        bool found = false;
        X509_NAME *issuer = X509_get_issuer_name(cert.handle());
        for(int i = 0; i < X509_NAME_entry_count(issuer); ++i)
        {
            X509_NAME_ENTRY *entb = X509_NAME_get_entry(issuer, i);
            if(OBJ_cmp(obja, X509_NAME_ENTRY_get_object(entb)) != 0)
                continue;

            char *val = nullptr;
            int size = ASN1_STRING_to_UTF8((unsigned char**)&val, X509_NAME_ENTRY_get_data(entb));
            found = value.compare(0, size_t(size), val, value.size()) == 0;
            OPENSSL_free(val);
            if(found)
                break;
        }
        if(!found)
            return -1;
    }
    return 0;
}

bool X509Crypto::isRSAKey() const
{
    EVP_PKEY *key = X509_get0_pubkey(cert.handle());
    return key && EVP_PKEY_base_id(key) == EVP_PKEY_RSA;
}

/**
 * Verify signature with RSA public key from X.509 certificate.
 *
 * @param digestMethod digest method (e.g NID_sha1 for SHA1, see openssl/obj_mac.h).
 * @param digest digest value, this value is compared with the digest value decrypted from the <code>signature</code>.
 * @param signature signature value, this value is decrypted to get the digest and compared with
 *        the digest value provided in <code>digest</code>.
 * @return returns <code>true</code> if the signature value matches with the digest, otherwise <code>false</code>
 *         is returned.
 * @throws IOException throws exception if X.509 certificate is not missing or does not have a RSA public key.
 */
bool X509Crypto::verify(const string &method, const vector<unsigned char> &digest, const vector<unsigned char> &signature)
{
    if(!cert)
        THROW("X.509 certificate parameter is not set in RSACrypt, can not verify signature.");

    if(signature.empty())
        THROW("Signature value is empty.");

    EVP_PKEY *key = X509_get0_pubkey(cert.handle());
    if(!key)
        THROW("Certificate does not have a public key, can not verify signature.");

    SCOPE(EVP_PKEY_CTX, ctx, EVP_PKEY_CTX_new(key, nullptr));
    switch(EVP_PKEY_base_id(key))
    {
    case EVP_PKEY_RSA:
        break;
#ifndef OPENSSL_NO_ECDSA
    case EVP_PKEY_EC:
    {
        SCOPE(ECDSA_SIG, sig, ECDSA_SIG_new());
        ECDSA_SIG_set0(sig.get(),
            BN_bin2bn(signature.data(), int(signature.size()/2), nullptr),
            BN_bin2bn(&signature[signature.size()/2], int(signature.size()/2), nullptr));
        vector<unsigned char> asn1 = i2d(sig.get(), i2d_ECDSA_SIG);
        return ctx &&
            EVP_PKEY_verify_init(ctx.get()) == 1 &&
            EVP_PKEY_verify(ctx.get(), asn1.data(), asn1.size(), digest.data(), digest.size()) == 1;
    }
#endif
    default: THROW("Unsupported public key");
    }
    int nid = Digest::toMethod(method);
    if(Digest::isRsaPssUri(method))
    {
        return ctx &&
            EVP_PKEY_verify_init(ctx.get()) == 1 &&
            EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PSS_PADDING) == 1 &&
            EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx.get(), RSA_PSS_SALTLEN_DIGEST) == 1 &&
            EVP_PKEY_CTX_set_signature_md(ctx.get(), EVP_get_digestbynid(nid)) == 1 &&
            EVP_PKEY_verify(ctx.get(), signature.data(), signature.size(), digest.data(), digest.size()) == 1;
    }
    else
    {
        size_t size = 0;
        if(!ctx ||
            EVP_PKEY_verify_recover_init(ctx.get()) <= 0 ||
            EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING) <= 0 ||
            EVP_PKEY_verify_recover(ctx.get(), nullptr, &size, signature.data(), signature.size()) <= 0)
            return false;
        vector<unsigned char> decrypted(size);
        if(EVP_PKEY_verify_recover(ctx.get(), decrypted.data(), &size, signature.data(), signature.size()) <= 0)
            return false;
        decrypted.resize(size);
        const unsigned char *p = decrypted.data();
        SCOPE(X509_SIG, sig, d2i_X509_SIG(nullptr, &p, long(decrypted.size())));
        if(!sig)
            return false;
        const X509_ALGOR *algor = nullptr;
        const ASN1_OCTET_STRING *value = nullptr;
        X509_SIG_get0(sig.get(), &algor, &value);

        if(algor->parameter && ASN1_TYPE_get(algor->parameter) != V_ASN1_NULL)
            return false;
        return nid == OBJ_obj2nid(algor->algorithm) &&
            size_t(value->length) == digest.size() &&
            memcmp(value->data, digest.data(), digest.size()) == 0;
    }
}
