// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include <SignatureCAdES_B.h>

namespace digidoc
{

class TS;
class SignatureCAdES_T: public SignatureCAdES_B
{
public:
    SignatureCAdES_T(Signer *signer): SignatureCAdES_B(signer) {}
    SignatureCAdES_T(const std::vector<unsigned char> &data): SignatureCAdES_B(data) {}

    std::string trustedSigningTime() const override;
    void validate(const std::string &policy) const override;
    void extendSignatureProfile(const std::string &profile) override;

    X509Cert TimeStampCertificate() const override;
    std::string TimeStampTime() const override;

private:
    DISABLE_COPY(SignatureCAdES_T);

    TS ts() const;
};

}
