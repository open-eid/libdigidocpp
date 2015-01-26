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

#include "X509Cert.h"

#include "log.h"
#include "crypto/OpenSSLHelpers.h"
#include "crypto/X509Crypto.h"

#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <functional>
#include <sstream>
#include <cstring>

using namespace digidoc;
using namespace std;

namespace digidoc
{
class X509CertPrivate
{
public:
    /**
     * Converts X509_NAME struct to string.
     *
     * @param name X509_NAME struct that is converted to string.
     * @return converted value of X509_NAME.
     * @throws IOException throws exception if conversion failed.
     */
    static string toString(X509_NAME* name, const string &obj)
    {
        if(!name)
            THROW_OPENSSLEXCEPTION("Failed to convert X.509 certificate subject");

        string str;
        if(!obj.empty())
        {
            for(int i = 0; i < X509_NAME_entry_count(name); ++i)
            {
                X509_NAME_ENTRY *e = X509_NAME_get_entry(name, i);
                if(obj != OBJ_nid2sn(OBJ_obj2nid(X509_NAME_ENTRY_get_object(e))))
                    continue;

                char *data = nullptr;
                int size = ASN1_STRING_to_UTF8((unsigned char**)&data, X509_NAME_ENTRY_get_data(e));
                str.append(data, size);
                OPENSSL_free(data);
            }
        }
        else
        {
            BIO* mem = BIO_new(BIO_s_mem());
            if(!mem)
                THROW_OPENSSLEXCEPTION("Failed to allocate memory for X509_NAME conversion");

            // Convert the X509_NAME struct to string.
            if(X509_NAME_print_ex(mem, name, 0, XN_FLAG_RFC2253) < 0)
            {
                BIO_free(mem);
                THROW_OPENSSLEXCEPTION("Failed to convert X509_NAME struct to string");
            }

            BUF_MEM *data = nullptr;
            BIO_get_mem_ptr(mem, &data);
            str.append(data->data, data->length);
            BIO_free(mem);
        }

        return str;
    }
};

}


/**
 * @class digidoc::X509Cert
 *
 * @brief Wrapper for OpenSSL X509 certificate structure.
 */

/**
 * @enum digidoc::X509Cert::Format
 * Binary encoding format
 *
 * @var digidoc::X509Cert::Der
 * ASN.1 syntax
 *
 * @var digidoc::X509Cert::Pem
 * Base64 encoded ASN.1 syntax
 */

/**
 * @enum digidoc::X509Cert::KeyUsage
 * Key usage bits defined in certificate
 *
 * @var digidoc::X509Cert::DigitalSignature
 * @var digidoc::X509Cert::NonRepudiation
 * Used for signing certificate selection in the current library
 *
 * @var digidoc::X509Cert::KeyEncipherment
 * @var digidoc::X509Cert::DataEncipherment
 * @var digidoc::X509Cert::KeyAgreement
 * @var digidoc::X509Cert::KeyCertificateSign
 * @var digidoc::X509Cert::CRLSign
 * @var digidoc::X509Cert::EncipherOnly
 * @var digidoc::X509Cert::DecipherOnly
 */

/**
 * Creates copy of the OpenSSL X509 certificate.
 *
 * @param cert X509 certificate structure to be wrapped.
 */
X509Cert::X509Cert(X509* cert)
    : cert(X509_dup(cert), function<void(X509*)>(X509_free))
{
}

/**
 * Creates X509 certificate from bytes.
 *
 * @param bytes X509 certificate in bytes.
 * @param format <code>Format</code> input bytes format
 * @throws Exception throws exception if X509 certificate parsing failed.
 */
X509Cert::X509Cert(const vector<unsigned char> &bytes, Format format)
    : X509Cert(bytes.size() > 0 ? &bytes[0] : nullptr, bytes.size(), format)
{
}

/**
 * Creates X509 certificate from bytes.
 *
 * @param bytes X509 certificate in bytes.
 * @param size of X509 certificate in bytes.
 * @param format <code>Format</code> input bytes format
 * @throws Exception throws exception if X509 certificate parsing failed.
 */
X509Cert::X509Cert(const unsigned char *bytes, size_t size, Format format)
{
    if(!bytes || size == 0)
        THROW("No bytes given to parse X509.");
    if(format == Der)
    {
        const unsigned char *p = bytes;
        cert.reset(d2i_X509(0, &p, (unsigned int)size), function<void(X509*)>(X509_free));
    }
    else
    {
        BIO *bio = BIO_new_mem_buf((void*)bytes, int(size));
        cert.reset(PEM_read_bio_X509(bio, 0, 0, 0), function<void(X509*)>(X509_free));
        BIO_free(bio);
    }
    if(!cert)
        THROW_OPENSSLEXCEPTION("Failed to parse X509 certificate from bytes given");
}

/**
 * Creates X509 certificate from path.
 *
 * @param path X509 certificate path.
 * @param format <code>Format</code> input bytes format
 * @throws Exception throws exception if X509 certificate parsing failed.
 */
X509Cert::X509Cert(const string &path, Format format)
{
    if(path.empty())
        THROW("No path given to parse X509.");
    SCOPE2(BIO, bio, BIO_new_file(path.c_str(), "rb"), BIO_free_all);
    if(!bio)
        THROW_OPENSSLEXCEPTION("Failed to open X.509 certificate file '%s'", path.c_str());
    if(format == Der)
        cert.reset(d2i_X509_bio(bio.get(), 0), function<void(X509*)>(X509_free));
    else
        cert.reset(PEM_read_bio_X509(bio.get(), 0, 0, 0), function<void(X509*)>(X509_free));
    if(!cert)
        THROW_OPENSSLEXCEPTION("Failed to parse X509 certificate from bytes given");
}

/**
 * Copy constructor.
 */
X509Cert::X509Cert(const X509Cert &other)
 : cert(other.cert)
{
}

/**
 * Move constructor.
 */
X509Cert::X509Cert(X509Cert &&other)
 : cert(move(other.cert))
{
}

/**
 * Clean up underlying X509 data.
 */
X509Cert::~X509Cert()
{
}

/**
 * Encodes the X509 certificate using DER encoding.
 */
X509Cert::operator vector<unsigned char>() const
{
    if(!cert)
        return vector<unsigned char>();
    vector<unsigned char> der(i2d_X509(cert.get(), 0), 0);
    if(der.empty())
        return der;
    unsigned char *p = &der[0];
    i2d_X509(cert.get(), &p);
    return der;
}

/**
 * Returns X.509 certificate serial number.
 *
 * @throws Exception exception is thrown if the serial is incorrect.
 */
string X509Cert::serial() const
{
    if(!cert)
        return string();
    string serial;
    SCOPE2(BIGNUM, bn, ASN1_INTEGER_to_BN(X509_get_serialNumber(cert.get()), 0), BN_free);
    if(!!bn)
    {
        char *str = BN_bn2dec(bn.get());
        if(str)
            serial = str;
        OPENSSL_free(str);
    }

    if(serial.empty())
        THROW_OPENSSLEXCEPTION("Failed to read certificate serial number from X.509 certificate");

    return serial;
}

/**
 * Returns issuer name as string.
 *
 * @param obj if set to empty string then returns whole issuer name. Otherwise, for example, if set to 
 * CN then returns Common name part from issuer name.
 * @throws Exception exception is throws if the conversion failed.
 */
string X509Cert::issuerName(const string &obj) const
{
    return cert ? X509CertPrivate::toString(X509_get_issuer_name(cert.get()), obj) : string();
}

/**
 * Returns current certificate key usage bits
 */
vector<X509Cert::KeyUsage> X509Cert::keyUsage() const
{
    if(!cert)
        return vector<X509Cert::KeyUsage>();
    SCOPE(ASN1_BIT_STRING, keyusage, (ASN1_BIT_STRING*)X509_get_ext_d2i(cert.get(), NID_key_usage, 0, 0));
    if(!keyusage)
        return vector<KeyUsage>();

    vector<KeyUsage> usage;
    for(int n = 0; n < 9; ++n)
    {
        if(ASN1_BIT_STRING_get_bit(keyusage.get(), n))
            usage.push_back(KeyUsage(n));
    }
    return usage;
}

/**
 * Returns current certificate policies
 */
vector<string> X509Cert::certificatePolicies() const
{
    if(!cert)
        return vector<string>();
    CERTIFICATEPOLICIES *cp = (CERTIFICATEPOLICIES*)X509_get_ext_d2i(cert.get(), NID_certificate_policies, 0, 0);
    if(!cp)
        return vector<string>();

    vector<string> pol;
    for(int i = 0; i < sk_POLICYINFO_num(cp); ++i)
    {
        string buf(80, 0);
        int len = OBJ_obj2txt(&buf[0], int(buf.size()), sk_POLICYINFO_value(cp, i)->policyid, 1);
        if(len == NID_undef)
            continue;
        buf.resize(len);
        pol.push_back(buf);
    }
    sk_POLICYINFO_pop_free(cp, POLICYINFO_free);
    return pol;
}

/**
 * Return subject name as string.
 *
 * @param obj empty string then returns whole issuer name. Otherwise, for example, if set to 
 * CN then returns Common name part from issuer name.
 * @throws Exception exception is throws if the conversion failed.
 */
string X509Cert::subjectName(const string &obj) const
{
    return cert ? X509CertPrivate::toString(X509_get_subject_name(cert.get()), obj) : string();
}

/**
 * Returns certificate internal handle (OpenSSL X509 struct)
 */
X509* X509Cert::handle() const
{
    return cert.get();
}

/**
 * Validates if certificate is in valid time slot
 *
 * @param t If param is 0 then current time is used, else defined time
 */
bool X509Cert::isValid(time_t *t) const
{
    if(!cert)
        THROW_OPENSSLEXCEPTION("Failed to validate cert");
    int notBefore = X509_cmp_time(cert->cert_info->validity->notBefore, t);
    int notAfter = X509_cmp_time(cert->cert_info->validity->notAfter, t);
    if(notBefore == 0 || notAfter == 0)
        THROW_OPENSSLEXCEPTION("Failed to validate cert");
    return notBefore < 0 && notAfter > 0;
}

/**
 * Negative operator to check if object is valid
 */
bool X509Cert::operator !() const
{
    return !cert;
}

/**
 * Assign operator to make copy of object
 */
X509Cert& X509Cert::operator =(const X509Cert &other)
{
    if(this != &other)
        cert = other.cert;
    return *this;
}

/**
 * Assign operator to make copy of object
 */
X509Cert& X509Cert::operator =(X509Cert &&other)
{
    if(this != &other)
        cert = move(other.cert);
    return *this;
}

/**
 * Equal operator to compare two objects
 */
bool X509Cert::operator ==(const X509Cert &other) const
{
    if(cert == other.cert)
        return true;
    if(!cert || !other.cert)
        return false;
    return X509_cmp(cert.get(), other.cert.get()) == 0;
}

/**
 * Not equal operator to compare two objects
 */
bool X509Cert::operator !=(const X509Cert &other) const
{
    return !operator ==(other);
}
