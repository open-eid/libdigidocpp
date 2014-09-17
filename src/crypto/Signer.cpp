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

#include "Signer.h"

#include "log.h"
#include "crypto/Digest.h"

using namespace digidoc;
using namespace std;

namespace digidoc
{
class SignerPrivate
{
public:
    string city, stateOrProvince, postalCode, countryName;
    vector<string> signerRoles;
};
}

/**
 * @class digidoc::Signer
 * @brief <code>Signer</code> interface. Provides interface for signing documents.
 * 
 * Digidoc LIB implements PKCS11, PKCS12, CNG
 * signer class that allows signing with EstId chip card. Other implementations may provide signing
 * implementation with other public-key cryptography systems.
 */

/**
 * Constructor
 */
Signer::Signer()
    : d(new SignerPrivate)
{
}

/**
 * Destructor
 */
Signer::~Signer()
{
    delete d;
}

/**
 * Sets signature production place according XAdES standard. Note that setting the signature production place is optional.
 * @param city
 * @param stateOrProvince
 * @param postalCode
 * @param countryName
 */
void Signer::setSignatureProductionPlace(const string &city,
    const string &stateOrProvince, const string &postalCode, const string &countryName)
{
    d->city = city;
    d->stateOrProvince = stateOrProvince;
    d->postalCode = postalCode;
    d->countryName = countryName;
}

/**
 * @fn digidoc::Signer::cert
 *
 * Returns signer certificate. Must be reimplemented when subclassing
 */

/**
 * Returns city from signature production place
 */
string Signer::city() const
{
    return d->city;
}

/**
 * Returns state from signature production place
 */
string Signer::stateOrProvince() const
{
    return d->stateOrProvince;
}

/**
 * Returns postal code from signature production place
 */
string Signer::postalCode() const
{
    return d->postalCode;
}

/**
 * Returns country from signature production place
 */
string Signer::countryName() const
{
    return d->countryName;
}

/**
 * Sets signature roles according XAdES standard. The parameter may contain the signer’s role and optionally the signer’s resolution. Note that only one  signer role value (i.e. one &lt;ClaimedRole&gt; XML element) should be used. 
 * If the signer role contains both role and resolution then they must be separated with a slash mark, e.g. “role / resolution”. 
 */
void Signer::setSignerRoles(const vector<string> &signerRoles)
{
    d->signerRoles = signerRoles;
}

/**
 * @fn digidoc::Signer::sign
 *
 * Signs message digest. Must be reimplemented when subclassing
 * @param method digest method to be used
 * @param digest digest to sign
 * @param signature signed result
 * @throws Exception throws exception on error 
 */

/**
 * Returns signer roles
 */
vector<string> Signer::signerRoles() const
{
    return d->signerRoles;
}
