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
#include "crypto/Signer.h"
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
string Signature::city() const { return {}; }

/**
 * Returns signature production country.
 */
string Signature::countryName() const { return {}; }

/**
 * Returns signed signature hash message imprint value (TM - OCSP Nonce, TS - TimeStamp value)
 */
vector<unsigned char> Signature::messageImprint() const { return {}; }

/**
 * Returns signature production postal code.
 */
string Signature::postalCode() const { return {}; }

/**
 * Returns signature production state or province.
 */
string Signature::stateOrProvince() const { return {}; }

/**
 * Returns signature production street address.
 */
string Signature::streetAddress() const { return {}; }

/**
 * Returns signer's roles.
 */
vector<string> Signature::signerRoles() const { return {}; }

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
void Signature::validate(const std::string & /*policy*/) const { validate(); }

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
void Signature::extendSignatureProfile(const string &profile) {
    struct ProfileSigner: public Signer
    {
        X509Cert cert() const { return X509Cert(); }
        vector<unsigned char> sign(const string &/*method*/, const vector<unsigned char> &/*digest*/) const { return {}; }
    } signer;
    signer.setProfile(profile);
    extendSignatureProfile(&signer);
}

/**
 * Extends signature to selected profile
 *
 * @param signer Signer parameters
 */
void Signature::extendSignatureProfile(Signer * /*signer*/) {}

/**
 * Returns signature policy when it is available or empty string.
 */
string Signature::policy() const { return {}; }

/**
 * Returns signature policy uri when it is available or empty string.
 */
string Signature::SPUri() const { return {}; }

/**
 * Returns signature OCSP producedAt timestamp.
 */
string Signature::OCSPProducedAt() const { return {}; }

/**
 * Returns signature OCSP responder certificate.
 */
X509Cert Signature::OCSPCertificate() const { return X509Cert(); }

/**
 * Returns signed signature message imprint in OCSP response nonce.
 * @deprecated Use messageImprint()
 */
vector<unsigned char> Signature::OCSPNonce() const { return messageImprint(); }

/**
 * Returns signature TimeStampToken certificate.
 */
X509Cert Signature::TimeStampCertificate() const { return X509Cert(); }

/**
 * Returns signature TimeStampToken time.
 */
string Signature::TimeStampTime() const { return {}; }

/**
 * Returns signature Archive TimeStampToken certificate.
 */
X509Cert Signature::ArchiveTimeStampCertificate() const { return X509Cert(); }

/**
 * Returns signature Archive TimeStampToken time.
 */
string Signature::ArchiveTimeStampTime() const { return {}; }

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
    if(d->result == Unknown)
    {
        try
        {
            s->validate(POLv1);
            d->result = NonQSCD;
        }
        catch(const Exception &e)
        {
            parseException(e);
        }
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
