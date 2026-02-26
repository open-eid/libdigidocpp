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

#include "ASiC_E.h"
#include "ASiC_S.h"
#include "Conf.h"
#include "crypto/Digest.h"
#include "crypto/X509Cert.h"
#include "util/log.h"

#include <openssl/x509.h>

#include <algorithm>
#include <map>
#include <optional>

using namespace digidoc;
using namespace std;

class Signer::Private
{
public:
    optional<string> method;
    string profile{ASiC_E::ASIC_TS_PROFILE};
    string userAgent;
    string city, streetAddress, stateOrProvince, postalCode, countryName;
    vector<string> signerRoles;
    bool ENProfile = false;
};

/**
 * @class digidoc::Signer
 * @brief <code>Signer</code> interface. Provides interface for signing documents.
 * 
 * Digidoc LIB implements PKCS11, PKCS12, Windows Crypto
 * signer class that allows signing with various tokens. Other implementations may provide signing
 * implementation with other public-key cryptography systems.
 */

/**
 * Constructor
 */
Signer::Signer()
    : d(make_unique<Private>())
{}

/**
 * Destructor
 */
Signer::~Signer() = default;

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
 * Sets signature production place according XAdES EN standard. Note that setting the signature production place is optional.
 * @since 3.13.0
 * @param city
 * @param streetAddress
 * @param stateOrProvince
 * @param postalCode
 * @param countryName
 */
void Signer::setSignatureProductionPlaceV2(const string &city, const string &streetAddress,
    const string &stateOrProvince, const string &postalCode, const string &countryName)
{
    if(!streetAddress.empty())
        setENProfile(true);
    d->city = city;
    d->streetAddress = streetAddress;
    d->stateOrProvince = stateOrProvince;
    d->postalCode = postalCode;
    d->countryName = countryName;
}

/**
 * Sets additional User-Agent info that is sent to TSA or OCSP service
 * @since 4.1.0
 * @param userAgent
 */
void Signer::setUserAgent(const string &userAgent)
{
    d->userAgent = userAgent;
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
 * Returns streetAddress from signature production place
 * @since 3.13.0
 */
string Signer::streetAddress() const
{
    return d->streetAddress;
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
 * Returns signing profile
 */
string Signer::profile() const
{
    return d->profile;
}

/**
 * Returns country from signature production place
 */
string Signer::countryName() const
{
    return d->countryName;
}

/**
 * Set signing profile
 *
 * - time-stamp
 * - time-stamp-archive
 */
void Signer::setProfile(const string &profile)
{
    static const map<string_view,string_view> profiles {
        {{}, ASiC_E::ASIC_TS_PROFILE},
        {"BES", "BES"},
        {"EPES", "EPES"},
        {"TS", ASiC_E::ASIC_TS_PROFILE},
        {"TSA", ASiC_E::ASIC_TSA_PROFILE},
        {ASiC_E::ASIC_TS_PROFILE, ASiC_E::ASIC_TS_PROFILE},
        {ASiC_E::ASIC_TSA_PROFILE, ASiC_E::ASIC_TSA_PROFILE},
        {ASiC_S::ASIC_TST_PROFILE, ASiC_S::ASIC_TST_PROFILE},
        {"time-stamp-token", ASiC_S::ASIC_TST_PROFILE}
    };
    if(auto it = profiles.find(profile); it != profiles.cend())
        d->profile = it->second;
    else
        THROW("Unsupported profile: %s", profile.c_str());
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
 * @fn std::vector<unsigned char> digidoc::Signer::sign(const std::string &method, const std::vector<unsigned char> &digest)
 *
 * Signs message digest. Must be reimplemented when subclassing
 * @param method digest method to be used
 * @param digest digest to sign
 * @return signature signed result
 * @throws Exception throws exception on error
 */

/**
 * Returns signer roles
 */
vector<string> Signer::signerRoles() const
{
    return d->signerRoles;
}

/**
 * Sets signature method
 */
void Signer::setMethod(const string &method)
{
    if(method.empty())
        d->method.reset();
    else
        d->method = method;
}

/**
 * Toggle XAdES EN profile usage on signing
 * @since 3.13.0
 */
void Signer::setENProfile(bool enable)
{
    d->ENProfile = enable;
}

/**
 * Gets signature method
 */
string Signer::method() const
{
    X509Cert c = cert();
    if(EVP_PKEY *key = X509_get0_pubkey(c.handle());
        key && EVP_PKEY_base_id(key) == EVP_PKEY_EC && !d->method)
    {
        switch(EVP_PKEY_bits(key)) {
        case 224: return URI_SHA224;
        case 256: return URI_SHA256;
        case 384: return URI_SHA384;
        default: return URI_SHA512;
        }
    }
    return d->method.value_or(CONF(signatureDigestUri));
}

/**
 * Additional User-Agent info that is sent to TSA or OCSP service
 */
string Signer::userAgent() const
{
    return d->userAgent;
}

/**
 * Use XAdES EN profile
 * @since 3.13.0
 */
bool Signer::usingENProfile() const
{
    return d->ENProfile;
}
