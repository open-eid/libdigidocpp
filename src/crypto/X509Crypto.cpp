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

#include "log.h"
#include "crypto/Digest.h"
#include "crypto/OpenSSLHelpers.h"
#include "util/File.h"

#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/ts.h>
#include <openssl/x509v3.h>

#include <cstring>
#include <iterator>
#include <set>

using namespace digidoc;
using namespace std;

#if OPENSSL_VERSION_NUMBER >= 0x10010000L
/*-
 * IssuerSerial ::= SEQUENCE {
 *         issuer                   GeneralNames,
 *         serialNumber             CertificateSerialNumber
 *         }
 */
using ESS_ISSUER_SERIAL = struct ESS_issuer_serial {
    STACK_OF(GENERAL_NAME) *issuer;
    ASN1_INTEGER *serial;
};

ASN1_SEQUENCE(ESS_ISSUER_SERIAL) = {
        ASN1_SEQUENCE_OF(ESS_ISSUER_SERIAL, issuer, GENERAL_NAME),
        ASN1_SIMPLE(ESS_ISSUER_SERIAL, serial, ASN1_INTEGER)
} static_ASN1_SEQUENCE_END(ESS_ISSUER_SERIAL)
IMPLEMENT_ASN1_FUNCTIONS_const(ESS_ISSUER_SERIAL)
#else
static int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    if(!r || !s) return 0;
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;
    return 1;
}
#endif

/**
 * Initialize RSA crypter.
 *
 * @param cert X.509 certificate.
 */
X509Crypto::X509Crypto(X509Cert cert)
 : cert(std::move(cert))
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
    static const std::set<std::string> list{
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
        if(list.find(obj) == list.end())
            continue;

        ASN1_OBJECT *obja = OBJ_txt2obj(obj.c_str(), 0);
        string tmp = nameitem.substr(pos+1, pos-old);

        string value;
        char data[] = "00";
        for(string::const_iterator i = tmp.cbegin(); i != tmp.cend(); ++i)
        {
            if(*i == '\\' && distance(i, tmp.cend()) > 2 && isxdigit(*(i+1)) && isxdigit(*(i+2)))
            {
                data[0] = *(++i);
                data[1] = *(++i);
                value += static_cast<char>(strtoul(data, nullptr, 16));
            }
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

            char *data = nullptr;
            int size = ASN1_STRING_to_UTF8((unsigned char**)&data, X509_NAME_ENTRY_get_data(entb));
            found = value.compare(0, size_t(size), data, value.size()) == 0;
            OPENSSL_free(data);
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
    SCOPE(EVP_PKEY, key, X509_get_pubkey(cert.handle()));
    return key.get() && EVP_PKEY_base_id(key.get()) == EVP_PKEY_RSA;
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

    SCOPE(EVP_PKEY, key, X509_get_pubkey(cert.handle()));
    if(!key)
        THROW("Certificate does not have a public key, can not verify signature.");

    int result = 0;
    switch(EVP_PKEY_base_id(key.get()))
    {
    case EVP_PKEY_RSA:
    {
        SCOPE(RSA, rsa, EVP_PKEY_get1_RSA(key.get()));
#if OPENSSL_VERSION_NUMBER < 0x10010000L
        result = RSA_verify(Digest::toMethod(method), digest.data(), (unsigned int)digest.size(),
            const_cast<unsigned char*>(signature.data()), (unsigned int)signature.size(), rsa.get());
#else
        vector<unsigned char> out(size_t(RSA_size(rsa.get())));
        int size = RSA_public_decrypt(int(signature.size()), signature.data(), out.data(), rsa.get(), RSA_PKCS1_PADDING);
        if(size <= 0)
            break;
        out.resize(size_t(size));

        const unsigned char *p = out.data();
        SCOPE(X509_SIG, sig, d2i_X509_SIG(nullptr, &p, long(out.size())));
        if(!sig)
            break;
        const X509_ALGOR *algor = nullptr;
        const ASN1_OCTET_STRING *value = nullptr;
        X509_SIG_get0(sig.get(), &algor, &value);

        if(algor->parameter && ASN1_TYPE_get(algor->parameter) != V_ASN1_NULL)
            break;
        if(Digest::toMethod(method) == OBJ_obj2nid(algor->algorithm) &&
            size_t(value->length) == digest.size() &&
            memcmp(value->data, digest.data(), digest.size()) == 0)
            result = 1;
#endif
        break;
    }
#ifndef OPENSSL_NO_ECDSA
    case EVP_PKEY_EC:
    {
        SCOPE(EC_KEY, ec, EVP_PKEY_get1_EC_KEY(key.get()));
        SCOPE(ECDSA_SIG, sig, ECDSA_SIG_new());
        ECDSA_SIG_set0(sig.get(),
            BN_bin2bn(signature.data(), int(signature.size()/2), nullptr),
            BN_bin2bn(&signature[signature.size()/2], int(signature.size()/2), nullptr));
        result = ECDSA_do_verify(digest.data(), int(digest.size()), sig.get(), ec.get());
        break;
    }
#endif
    default: THROW("Unsupported public key");
    }
    return result == 1;
}
