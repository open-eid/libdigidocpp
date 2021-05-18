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

#include "ASiC_S.h"
#include "Signature.h"

#include "crypto/TS.h"

namespace digidoc
{

class SignatureTST final: public Signature
{
public:
    SignatureTST(std::unique_ptr<std::istream> sigdata, ASiC_S *asicSDoc);
    ~SignatureTST();

    std::string trustedSigningTime() const final;

    X509Cert TimeStampCertificate() const final;
    std::string TimeStampTime() const final;

    // DSig properties
    std::string id() const final;
    std::string claimedSigningTime() const final;
    X509Cert signingCertificate() const final;
    std::string signatureMethod() const final;
    void validate() const final;
    std::vector<unsigned char> dataToSign() const final;
    void setSignatureValue(const std::vector<unsigned char> &signatureValue) final;

    // Xades properties
    std::string profile() const final;

private:
    DISABLE_COPY(SignatureTST);
    ASiC_S *asicSDoc = nullptr;
    TS* timestampToken = nullptr;
};

}
