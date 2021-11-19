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

#pragma once

#include "SignatureXAdES_T.h"


namespace digidoc
{

class OCSP;
class SignatureXAdES_LT: public SignatureXAdES_T
{
public:
    SignatureXAdES_LT(unsigned int id, ASiContainer *bdoc, Signer *signer);
    SignatureXAdES_LT(std::stringstream &&sigdata, ASiContainer *bdoc, bool relaxSchemaValidation = false);

    std::string trustedSigningTime() const override;

    std::vector<unsigned char> messageImprint() const override;
    X509Cert OCSPCertificate() const override;
    std::string OCSPProducedAt() const override;
    void validate(const std::string &policy) const override;
    void extendSignatureProfile(const std::string &profile) override;

private:
    DISABLE_COPY(SignatureXAdES_LT);

    void addOCSPValue(const std::string &id, const OCSP &ocsp);
    void addCertificateValue(const std::string& certId, const X509Cert& x509);
    OCSP getOCSPResponseValue() const;
};

}
