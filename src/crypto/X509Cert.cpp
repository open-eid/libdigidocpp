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

#include <openssl/asn1t.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <functional>
#include <sstream>
#include <cstring>

using namespace digidoc;
using namespace std;

#if OPENSSL_VERSION_NUMBER < 0x10010000L
static const ASN1_TIME *X509_get0_notBefore(const X509 *x)
{
    return x->cert_info->validity->notBefore;
}

static const ASN1_TIME *X509_get0_notAfter(const X509 *x)
{
    return x->cert_info->validity->notAfter;
}
#endif

/**
 * SemanticsInformation ::= SEQUENCE {
 *        semanticsIdentifier         OBJECT IDENTIFIER OPTIONAL,
 *        nameRegistrationAuthorities NameRegistrationAuthorities OPTIONAL
 *        }
 */
typedef struct SemanticsInformation_st {
    ASN1_OBJECT *semanticsIdentifier;
    //NameRegistrationAuthorities nameRegistrationAuthorities;
} SemanticsInformation;
DECLARE_ASN1_FUNCTIONS(SemanticsInformation)

/**
 * QcType ::= SEQUENCE OF OBJECT IDENTIFIER
 */
typedef STACK_OF(ASN1_OBJECT) QcType;
DECLARE_ASN1_FUNCTIONS(QcType)

/**
 * QCStatement ::= SEQUENCE {
 *     statementId        OBJECT IDENTIFIER,
 *     statementInfo      ANY DEFINED BY statementId OPTIONAL}
 */
typedef struct QCStatement_st {
    ASN1_OBJECT *statementId;
#ifndef TEMPLATE
    ASN1_TYPE *statementInfo;
#else
    union {
        SemanticsInformation *semanticsInformation;
        ASN1_TYPE *other;
    } statementInfo;
#endif
} QCStatement;
DECLARE_ASN1_FUNCTIONS(QCStatement)

/**
 * QCStatements ::= SEQUENCE OF QCStatement
 */
typedef STACK_OF(QCStatement) QCStatements;
DECLARE_ASN1_FUNCTIONS(QCStatements)

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
 * https://www.ietf.org/rfc/rfc3739.txt - id-etsi-qcs-QcCompliance
 */
const string X509Cert::QC_COMPLIANT = "0.4.0.1862.1.1";
/**
 * https://www.ietf.org/rfc/rfc3739.txt - id-etsi-qcs-QcSSCD
 */
const string X509Cert::QC_SSCD = "0.4.0.1862.1.4";
/**
 * https://www.ietf.org/rfc/rfc3739.txt - id-etsi-qcs-QcPDS
 */
const string X509Cert::QC_QCP = "0.4.0.1862.1.5";
/**
 * https://www.ietf.org/rfc/rfc3739.txt - id-etsi-qcs-QcType
 */
const string X509Cert::QC_QCT = "0.4.0.1862.1.6";
/**
 * https://www.ietf.org/rfc/rfc3739.txt - id-qcs-pkixQCSyntax-v1
 */
const string X509Cert::QC_SYNTAX1 = "1.3.6.1.5.5.7.11.1";
/**
 * https://www.ietf.org/rfc/rfc3739.txt - id-qcs-pkixQCSyntax-v2
 */
const string X509Cert::QC_SYNTAX2 = "1.3.6.1.5.5.7.11.2";
/**
 * http://www.etsi.org/deliver/etsi_en/319400_319499/31941201/01.01.01_60/en_31941201v010101p.pdf - id-etsi-qcs-semanticsId-natural
 */
const string X509Cert::QCS_NATURAL = "0.4.0.194121.1.1";
/**
 * http://www.etsi.org/deliver/etsi_en/319400_319499/31941201/01.01.01_60/en_31941201v010101p.pdf - id-etsi-qcs-semanticsId-legal
 */
const string X509Cert::QCS_LEGAL = "0.4.0.194121.1.2";
/**
 * http://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.01.01_60/en_31941205v020101p.pdf - id-etsi-qct-esign
 */
const string X509Cert::QCT_ESIGN = "0.4.0.1862.1.6.1";
/**
 * http://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.01.01_60/en_31941205v020101p.pdf - id-etsi-qct-eseal
 */
const string X509Cert::QCT_ESEAL = "0.4.0.1862.1.6.2";
/**
 * http://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.01.01_60/en_31941205v020101p.pdf - id-etsi-qct-web
 */
const string X509Cert::QCT_WEB = "0.4.0.1862.1.6.3";
/**
 * http://www.etsi.org/deliver/etsi_ts/101400_101499/101456/01.04.03_60/ts_101456v010403p.pdf
 */
const string X509Cert::QCP_PUBLIC_WITH_SSCD = "0.4.0.1456.1.1";
/**
 * http://www.etsi.org/deliver/etsi_ts/101400_101499/101456/01.04.03_60/ts_101456v010403p.pdf
 */
const string X509Cert::QCP_PUBLIC = "0.4.0.1456.1.2";
/**
 * http://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.01.01_60/en_31941102v020101p.pdf
 */
const string X509Cert::QCP_NATURAL = "0.4.0.194112.1.0";
/**
 * http://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.01.01_60/en_31941102v020101p.pdf
 */
const string X509Cert::QCP_LEGAL = "0.4.0.194112.1.1";
/**
 * http://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.01.01_60/en_31941102v020101p.pdf
 */
const string X509Cert::QCP_NATURAL_QSCD = "0.4.0.194112.1.2";
/**
 * http://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.01.01_60/en_31941102v020101p.pdf
 */
const string X509Cert::QCP_LEGAL_QSCD = "0.4.0.194112.1.3";
/**
 * http://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.01.01_60/en_31941102v020101p.pdf
 */
const string X509Cert::QCP_WEB = "0.4.0.194112.1.4";

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
    : X509Cert(bytes.data(), bytes.size(), format)
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
X509Cert::X509Cert(const X509Cert &other) = default;

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
X509Cert::~X509Cert() = default;

/**
 * Encodes the X509 certificate using DER encoding.
 */
X509Cert::operator vector<unsigned char>() const
{
    vector<unsigned char> der;
    if(!cert)
        return der;
    der.resize(size_t(i2d_X509(cert.get(), 0)), 0);
    if(der.empty())
        return der;
    unsigned char *p = der.data();
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
    string serial;
    if(!cert)
        return serial;
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
    return toString(X509_get_issuer_name, obj);
}

/**
 * Returns current certificate key usage bits
 */
vector<X509Cert::KeyUsage> X509Cert::keyUsage() const
{
    vector<KeyUsage> usage;
    if(!cert)
        return usage;
    SCOPE(ASN1_BIT_STRING, keyusage, (ASN1_BIT_STRING*)X509_get_ext_d2i(cert.get(), NID_key_usage, 0, 0));
    if(!keyusage)
        return usage;

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
    vector<string> pol;
    if(!cert)
        return pol;
    CERTIFICATEPOLICIES *cp = (CERTIFICATEPOLICIES*)X509_get_ext_d2i(cert.get(), NID_certificate_policies, 0, 0);
    if(!cp)
        return pol;
    for(int i = 0; i < sk_POLICYINFO_num(cp); ++i)
        pol.push_back(toOID(sk_POLICYINFO_value(cp, i)->policyid));
    sk_POLICYINFO_pop_free(cp, POLICYINFO_free);
    return pol;
}

/**
 * Return QCStatements info https://www.ietf.org/rfc/rfc3739.txt
 */
vector<string> X509Cert::qcStatements() const
{
    vector<string> result;
    if(!cert)
        return result;
    int pos = X509_get_ext_by_NID(cert.get(), NID_qcStatements, -1);
    if(pos == -1)
        return result;
    X509_EXTENSION *ext = X509_get_ext(cert.get(), pos);
    QCStatements *qc = (QCStatements*)ASN1_item_unpack(X509_EXTENSION_get_data(ext), ASN1_ITEM_rptr(QCStatements));
    if(!qc)
        return result;

    for(int i = 0; i < sk_num((const stack_st*)qc); ++i)
    {
        QCStatement *s = (QCStatement*)sk_value((const stack_st*)qc, i);
        string oid = toOID(s->statementId);
        if(oid == QC_SYNTAX2)
        {
#ifndef TEMPLATE
            SemanticsInformation *si = (SemanticsInformation*)ASN1_item_unpack(s->statementInfo->value.sequence, ASN1_ITEM_rptr(SemanticsInformation));
            if(!si)
                continue;
            oid = toOID(si->semanticsIdentifier);
#else
            oid = toOID(s->statementInfo.semanticsInformation->semanticsIdentifier);
#endif
            result.push_back(oid);
            SemanticsInformation_free(si);
        }
        else if(oid == QC_QCT)
        {
#ifndef TEMPLATE
            STACK_OF(ASN1_OBJECT) *qct = (STACK_OF(ASN1_OBJECT)*)ASN1_item_unpack(s->statementInfo->value.sequence, ASN1_ITEM_rptr(QcType));
            if(!qct)
                continue;
            for(int j = 0; j < sk_ASN1_OBJECT_num(qct); ++j)
            {
                oid = toOID(sk_ASN1_OBJECT_value(qct, j));
#else
#endif
                result.push_back(oid);
            }
            sk_ASN1_OBJECT_pop_free(qct, ASN1_OBJECT_free);
        }
        else
            result.push_back(oid);
    }
    typedef void (*cast_free) (void *);
    sk_pop_free((stack_st*)qc, (cast_free)QCStatement_free);
    return result;
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
    return toString(X509_get_subject_name, obj);
}

string X509Cert::toOID(ASN1_OBJECT *obj) const
{
    string oid(80, 0);
    oid.resize(size_t(OBJ_obj2txt(&oid[0], int(oid.size()), obj, 1)));
    return oid;
};

/**
 * Converts X509_NAME struct to string.
 *
 * @param func X509_NAME struct that is converted to string.
 * @param obj Optional parameter to get from X509_NAME (default CN).
 * @return converted value of X509_NAME.
 * @throws Exception throws exception if conversion failed.
 */
template<typename Func>
string X509Cert::toString(Func func, const string &obj) const
{
    string str;
    if(!cert)
        return str;
    X509_NAME* name = func(cert.get());
    if(!name)
        THROW_OPENSSLEXCEPTION("Failed to convert X.509 certificate subject");

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
        str.assign(data->data, data->length);
        BIO_free(mem);
    }

    return str;
}

/**
 * Returns certificate internal handle (OpenSSL X509 struct)
 */
X509* X509Cert::handle() const
{
    return cert.get();
}

/**
 * Rerturns true if certificate is CA
 */
bool X509Cert::isCA() const
{
    if(!cert)
        return false;
    SCOPE(BASIC_CONSTRAINTS, cons, (BASIC_CONSTRAINTS*)X509_get_ext_d2i(cert.get(), NID_basic_constraints, 0, 0));
    return cons && cons->ca > 0;
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
    int notBefore = X509_cmp_time(X509_get0_notBefore(cert.get()), t);
    int notAfter = X509_cmp_time(X509_get0_notAfter(cert.get()), t);
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
X509Cert& X509Cert::operator =(const X509Cert &other) = default;

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

ASN1_SEQUENCE(SemanticsInformation) = {
    ASN1_OPT(SemanticsInformation, semanticsIdentifier, ASN1_OBJECT)
    //ASN1_OPT(SemanticsInformation, nameRegistrationAuthorities, NameRegistrationAuthorities)
} ASN1_SEQUENCE_END(SemanticsInformation)
IMPLEMENT_ASN1_FUNCTIONS(SemanticsInformation)

ASN1_ITEM_TEMPLATE(QcType) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, statements, ASN1_OBJECT)
ASN1_ITEM_TEMPLATE_END(QcType)

#ifdef TEMPLATE
ASN1_ADB_TEMPLATE(statementdefault) = ASN1_SIMPLE(QCStatement, statementInfo.other, ASN1_ANY);
ASN1_ADB(QCStatement) = {
    ADB_ENTRY(NID_id_qt_cps, ASN1_SIMPLE(QCStatement, statementInfo.semanticsInformation, SemanticsInformation))
} ASN1_ADB_END(QCStatement, 0, statementId, 0, &statementdefault_tt, NULL);
#endif

ASN1_SEQUENCE(QCStatement) = {
    ASN1_SIMPLE(QCStatement, statementId, ASN1_OBJECT),
#ifndef TEMPLATE
    ASN1_OPT(QCStatement, statementInfo, ASN1_ANY)
#else
    ASN1_ADB_OBJECT(QCStatement)
#endif
} ASN1_SEQUENCE_END(QCStatement)
IMPLEMENT_ASN1_FUNCTIONS(QCStatement)

ASN1_ITEM_TEMPLATE(QCStatements) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, statements, QCStatement)
ASN1_ITEM_TEMPLATE_END(QCStatements)
