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

#include "ASiCSDoc.h"
#include "Signature.h"

#include "crypto/TS.h"

namespace digidoc
{

class SignatureTST: public Signature
{
public:
    SignatureTST(std::istream &sigdata, ASiCSDoc *asicSDoc);
    virtual ~SignatureTST();

    virtual std::string trustedSigningTime() const override;

    X509Cert TimeStampCertificate() const override;
    std::string TimeStampTime() const override;

    // DSig properties
    std::string id() const override;
    std::string claimedSigningTime() const override;
    X509Cert signingCertificate() const override;
    std::string signatureMethod() const override;
    void validate() const override;
    std::vector<unsigned char> dataToSign() const override;
    void setSignatureValue(const std::vector<unsigned char> &signatureValue) override;

    // Xades properties
    std::string profile() const override;
    std::string city() const override;
    std::string stateOrProvince() const override;
    std::string postalCode() const override;
    std::string countryName() const override;
    std::vector<std::string> signerRoles() const override { return std::vector<std::string>(); }

    // Xades properties
    std::string streetAddress() const override;

private:
    DISABLE_COPY(SignatureTST);
    ASiCSDoc *asicSDoc;
    TS* timestampToken;
};

}
