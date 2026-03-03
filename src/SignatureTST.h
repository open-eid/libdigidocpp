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

#include "Signature.h"

#include <memory>

namespace digidoc
{
class ASiC_S;
class TS;
class ZipSerialize;

class SignatureTST final: public Signature
{
public:
    SignatureTST(bool manifest, const ZipSerialize &z, ASiC_S *asicSDoc);
    SignatureTST(ASiC_S *asicSDoc, Signer *signer);
    ~SignatureTST();

    std::vector<unsigned char> messageImprint() const override;
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
    void extendSignatureProfile(Signer *signer) final;

    // Xades properties
    std::string profile() const final;

    //TSA profile properties
    std::vector<TSAInfo> ArchiveTimeStamps() const final;

    void save(const ZipSerialize &s) const;

private:
    DISABLE_COPY(SignatureTST);
    ASiC_S *asicSDoc {};
    std::unique_ptr<TS> timestampToken;
    struct Data;
    std::vector<Data> metadata;
};

}
