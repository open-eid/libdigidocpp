// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "SignatureXAdES_T.h"


namespace digidoc
{

class OCSP;
class SignatureXAdES_LT: public SignatureXAdES_T
{
public:
    SignatureXAdES_LT(const std::shared_ptr<Signatures> &signatures, unsigned int id, ASiContainer *bdoc, Signer *signer);
    SignatureXAdES_LT(const std::shared_ptr<Signatures> &signatures, XMLNode s, ASiContainer *container);

    std::string trustedSigningTime() const override;

    std::vector<unsigned char> messageImprint() const override;
    X509Cert OCSPCertificate() const override;
    std::string OCSPProducedAt() const override;
    void validate(const std::string &policy) const override;
    void extendSignatureProfile(Signer *signer) override;

private:
    DISABLE_COPY(SignatureXAdES_LT);

    void addOCSPValue(const std::string &id, const OCSP &ocsp);
    void addCertificateValue(const std::string& certId, const X509Cert& x509);
    OCSP getOCSPResponseValue() const;
};

}
