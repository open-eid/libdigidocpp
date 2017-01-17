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

#include "crypto/X509Cert.h"

using namespace digidoc;
using namespace std;

/**
 * @class digidoc::Signature
 *
 * @brief <code>Signature</code> interface. Provides interface for handling a signature and the corresponding OCSP response properties.
 */

/**
 * @fn digidoc::Signature::Signature
 *
 * Creates an new empty signature.
 */

/**
 * @fn digidoc::Signature::~Signature
 *
 * Releases signature.
 */

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
 * @fn digidoc::Signature::profile
 *
 * Returns signature profile.
 */

/**
 * @fn digidoc::Signature::validate
 *
 * Validates signature
 */

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
void Signature::extendSignatureProfile(const string &)
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
 * Returns signature OCSP response nonce.
 */
vector<unsigned char> Signature::OCSPNonce() const
{
    return vector<unsigned char>();
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
