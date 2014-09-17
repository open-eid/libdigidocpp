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
 * Creates an new empty signature.
 */
Signature::Signature()
{
}

/**
 * Releases signature.
 */
Signature::~Signature()
{
}

/**
 * @fn digidoc::Signature::id
 *
 * Returns signature id.
 */

/**
 * @fn digidoc::Signature::city
 *
 * Returns signature production city.
 */

/**
 * @fn digidoc::Signature::countryName
 *
 * Returns signature production country.
 */

/**
 * @fn digidoc::Signature::postalCode
 *
 * Returns signature production postal code.
 */

/**
 * @fn digidoc::Signature::stateOrProvince
 *
 * Returns signature production state or province.
 */

/**
 * @fn digidoc::Signature::signerRoles
 *
 * Returns signer's roles.
 */

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
 * @fn digidoc::Signature::signingTime
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
 * Returns BDoc signature policy. If container is DDoc returns empty string.
 */
string Signature::policy() const
{
    return string();
}

/**
 * Returns BDoc signature policy uri. If container is DDoc returns empty string.
 */
string Signature::SPUri() const
{
    return string();
}

/**
 * Returns signature OCSP producedAt timestamp.
 */
string Signature::producedAt() const
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
vector<unsigned char> Signature::nonce() const
{
    return vector<unsigned char>();
}

/**
 * Returns signature TimeStampToken certificate.
 */
X509Cert Signature::TSCertificate() const
{
    return X509Cert();
}

/**
 * Returns signature TimeStampToken time.
 */
string Signature::TSTime() const
{
    return string();
}
