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

#include "crypto/OpenSSLHelpers.h"

#include <openssl/ts.h>

#include <algorithm>
#include <array>
#include <charconv>

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
    : cert(std::move(cert))
{}

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
 */
int X509Crypto::compareIssuerToString(string_view name) const
{
    static const array list {
        "CN", "commonName",
        "L", "localityName",
        "ST", "stateOrProvinceName",
        "O", "organizationName",
        "OU", "organizationalUnitName",
        "C", "countryName",
        "STREET", "street", "streetAddress",
        "DC", "domainComponent",
        "UID", "userId"
    };

    for(size_t old = 0, pos = name.find(','); ; pos = name.find(',', old))
    {
        if(pos == string::npos)
            pos = name.size();
        if(pos < old)
            break;
        if(name[pos-1] == '\\')
        {
            old = pos + 1;
            continue;
        }

        auto nameitem = name.substr(old, pos - old);
        old = pos + 1;

        if(pos = nameitem.find('=');
            pos == string::npos || pos == 0 || nameitem[pos-1] == '\\')
            continue;

        auto obj = find(list.cbegin(), list.cend(), nameitem.substr(0, pos));
        if(obj == list.cend())
            continue;

        if(*obj == "STREET"sv)
            obj++;
        ASN1_OBJECT *obja = OBJ_txt2obj(*obj, 0);
        if(!obja)
            continue;

        static const string_view escape = " #+,;<=>\\";
        string value(nameitem.substr(pos+1, pos-old));
        static const errc ok{};
        uint8_t result{};
        for(string::size_type pos = value.find('\\'); pos < value.size(); pos = value.find('\\', ++pos))
        {
            if(auto data = next(value.data(), pos + 1); from_chars(data, next(data, 2), result, 16).ec == ok)
            {
                value[pos] = char(result);
                value.erase(pos + 1, 2);
            }
            else if(escape.find(value[pos+1]) == string::npos)
                value.erase(pos, 1);
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
