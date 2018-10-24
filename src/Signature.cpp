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

#include "Signature.h"

#include "Exception.h"
#include "crypto/X509Cert.h"

#include <algorithm>

using namespace digidoc;
using namespace std;

/**
 * @class digidoc::Signature
 *
 * @brief <code>Signature</code> interface. Provides interface for handling a signature and the corresponding OCSP response properties.
 */

/**
 * http://open-eid.github.io/SiVa/siva/appendix/validation_policy/#POLv1
 *
 * @see validate(const std::string &policy) const
 */
const string Signature::POLv1 = "POLv1";

/**
 * http://open-eid.github.io/SiVa/siva/appendix/validation_policy/#POLv2
 *
 * @see validate(const std::string &policy) const
 */
const string Signature::POLv2 = "POLv2";

/**
 * Creates an new empty signature.
 */
Signature::Signature() = default;

/**
 * Releases signature.
 */
Signature::~Signature() = default;

/**
 * @fn digidoc::Signature::id
 *
 * Returns signature id.
 */

/**
 * Returns signature production city.
 */
string Signature::city() const { return string(); }

/**
 * Returns signature production country.
 */
string Signature::countryName() const { return string(); }

/**
 * Returns signed signature hash message imprint value (TM - OCSP Nonce, TS - TimeStamp value)
 */
vector<unsigned char> Signature::messageImprint() const { return vector<unsigned char>(); }

/**
 * Returns signature production postal code.
 */
string Signature::postalCode() const { return string(); }

/**
 * Returns signature production state or province.
 */
string Signature::stateOrProvince() const { return string(); }

/**
 * Returns signature production street address.
 */
string Signature::streetAddress() const { return string(); }

/**
 * Returns signer's roles.
 */
vector<string> Signature::signerRoles() const { return vector<string>(); }

/**
 * Return signer's certificate common name
 */
string Signature::signedBy() const { return signingCertificate().subjectName("CN"); }

/**
 * @fn digidoc::Signature::signatureMethod
 *
 * Returns signature method that was used for signing.
 */

/**
 * @fn digidoc::Signature::signingCertificate
 *
 * Returns signature certificate that was used for signing.
 */

/**
 * @fn digidoc::Signature::claimedSigningTime
 *
 * Returns signature computer time that was used for signing.
 */

/**
 * @fn digidoc::Signature::trustedSigningTime
 *
 * Time value that is regarded as trusted signing time, denoting the earliest
 * time when it can be trusted by the validation application (because proven by
 * some Proof-of-Existence present in the signature) that a signature has existed.
 */

/**
 * @fn digidoc::Signature::profile
 *
 * Returns signature profile.
 */

/**
 * @fn digidoc::Signature::validate() const
 *
 * Validates signature
 */

/**
 * Validates signature
 * @see POLv1
 * @see POLv2
 */
void Signature::validate(const std::string & /*policy*/) const
{
    validate();
}

/**
 * @fn digidoc::Signature::dataToSign
 *
 * Digest to sign with token
 */

/**
 * @fn digidoc::Signature::setSignatureValue
 *
 * Signed digest will be added to SignatureValue element
 * @see dataToSign
 */

/**
 * Extends signature to selected profile
 *
 * @param profile Target profile
 */
void Signature::extendSignatureProfile(const string & /*profile*/)
{}

/**
 * Returns signature policy when it is available or empty string.
 */
string Signature::policy() const
{
    return string();
}

/**
 * Returns signature policy uri when it is available or empty string.
 */
string Signature::SPUri() const
{
    return string();
}

/**
 * Returns signature OCSP producedAt timestamp.
 */
string Signature::OCSPProducedAt() const
{
    return string();
}

/**
 * Returns signature OCSP responder certificate.
 */
X509Cert Signature::OCSPCertificate() const
{
    return X509Cert();
}

/**
 * Returns signed signature message imprint in OCSP response nonce.
 * @deprecated use messageImprint
 */
vector<unsigned char> Signature::OCSPNonce() const
{
    return messageImprint();
}

/**
 * Returns signature TimeStampToken certificate.
 */
X509Cert Signature::TimeStampCertificate() const
{
    return X509Cert();
}

/**
 * Returns signature TimeStampToken time.
 */
string Signature::TimeStampTime() const
{
    return string();
}

/**
 * Returns signature Archive TimeStampToken certificate.
 */
X509Cert Signature::ArchiveTimeStampCertificate() const
{
    return X509Cert();
}

/**
 * Returns signature Archive TimeStampToken time.
 */
string Signature::ArchiveTimeStampTime() const
{
    return string();
}


struct Signature::Validator::Private
{
    Status result = Valid;
    std::string diagnostics;
    std::vector<Exception::ExceptionCode> warnings;
};

Signature::Validator::Validator(const Signature *s)
    : d(new Private)
{
    try
    {
        s->validate();
    }
    catch(const Exception &e)
    {
        parseException(e);
    }
    switch(d->result)
    {
    case Unknown:
        try
        {
            s->validate(POLv1);
            d->result = NonQSCD;
        }
        catch(const Exception &e)
        {
            parseException(e);
        }
        break;
    case Invalid:
        break;
    default:
        if(isTestCert(s->signingCertificate()) || isTestCert(s->OCSPCertificate()))
            d->result = std::max(d->result, Test);
        break;
    }
}

Signature::Validator::~Validator()
{
    delete d;
}

std::string Signature::Validator::diagnostics() const
{
    return d->diagnostics;
}

bool Signature::Validator::isTestCert(const X509Cert &cert)
{
    enum {
        UnknownType = 0,
        DigiIDType = 1 << 0,
        EstEidType = 1 << 1,
        MobileIDType = 1 << 2,
        OCSPType = 1 << 3,
        TempelType = 1 << 4,

        TestType = 1 << 5,
        DigiIDTestType = TestType|DigiIDType,
        EstEidTestType = TestType|EstEidType,
        MobileIDTestType = TestType|MobileIDType,
        OCSPTestType = TestType|OCSPType,
        TempelTestType = TestType|TempelType
    } type = UnknownType;
    for(const std::string &i: cert.certificatePolicies())
    {
        if(i.compare(0, 22, "1.3.6.1.4.1.10015.1.1.") == 0)
            type = EstEidType;
        else if(i.compare(0, 22, "1.3.6.1.4.1.10015.1.2.") == 0)
            type = DigiIDType;
        else if(i.compare(0, 22, "1.3.6.1.4.1.10015.1.3.") == 0 ||
            i.compare(0, 23, "1.3.6.1.4.1.10015.11.1.") == 0)
            type = MobileIDType;

        else if(i.compare(0, 22, "1.3.6.1.4.1.10015.3.1.") == 0)
            type = EstEidTestType;
        else if(i.compare(0, 22, "1.3.6.1.4.1.10015.3.2.") == 0)
            type = DigiIDTestType;
        else if(i.compare(0, 22, "1.3.6.1.4.1.10015.3.3.") == 0 ||
            i.compare(0, 23, "1.3.6.1.4.1.10015.11.3.") == 0)
            type = MobileIDTestType;
        else if(i.compare(0, 22, "1.3.6.1.4.1.10015.3.7.") == 0 ||
            (i.compare(0, 22, "1.3.6.1.4.1.10015.7.1.") == 0 &&
            cert.issuerName("CN").find("TEST") != std::string::npos) )
            type = TempelTestType;

        else if(i.compare(0, 22, "1.3.6.1.4.1.10015.7.1.") == 0 ||
            i.compare(0, 22, "1.3.6.1.4.1.10015.2.1.") == 0)
            type = TempelType;
    }
    return type & TestType;
}

void Signature::Validator::parseException(const Exception &e)
{
    for(const Exception &child: e.causes())
    {
        d->diagnostics += child.msg() + "\n";
        switch(child.code())
        {
        case Exception::ReferenceDigestWeak:
        case Exception::SignatureDigestWeak:
        case Exception::DataFileNameSpaceWarning:
        case Exception::IssuerNameSpaceWarning:
        case Exception::ProducedATLateWarning:
        case Exception::MimeTypeWarning:
            d->warnings.push_back(child.code());
            d->result = std::max(d->result, Warning);
            break;
        case Exception::CertificateIssuerMissing:
        case Exception::CertificateUnknown:
        case Exception::OCSPResponderMissing:
        case Exception::OCSPCertMissing:
            d->result = std::max(d->result, Unknown);
            break;
        default:
            d->result = std::max(d->result, Invalid);
        }
        parseException(child);
    }
}

Signature::Validator::Status Signature::Validator::status() const
{
    return d->result;
}

std::vector<Exception::ExceptionCode> Signature::Validator::warnings() const
{
    return d->warnings;
}
