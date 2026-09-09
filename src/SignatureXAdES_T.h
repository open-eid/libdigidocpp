// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "SignatureXAdES_B.h"

#include <functional>

namespace digidoc
{

class TS;
constexpr XMLName EncapsulatedTimeStamp {"EncapsulatedTimeStamp", XADES_NS};

class SignatureXAdES_T: public SignatureXAdES_B
{
public:
    using SignatureXAdES_B::SignatureXAdES_B;

    std::string trustedSigningTime() const override;
    std::vector<unsigned char> messageImprint() const override;

    X509Cert TimeStampCertificate() const override;
    std::string TimeStampTime() const override;
    void validate(const std::string &policy) const override;
    void extendSignatureProfile(Signer *signer) override;

protected:
    XMLNode unsignedSignatureProperties() const noexcept;
    TS TimeStamp() const;

    static TS verifyTS(XMLNode timestamp, Exception &exception,
        std::function<void (const Digest &, std::string_view)> &&calcDigest);

private:
    DISABLE_COPY(SignatureXAdES_T);
};

}
