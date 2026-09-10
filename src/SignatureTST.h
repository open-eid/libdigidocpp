// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

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
