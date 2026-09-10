// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include <Signature.h>

namespace digidoc
{

class Signer;
class SignatureCAdES_T;
class SignatureCAdESPrivate;
class X509Cert;

class SignatureCAdES_B: public Signature
{
public:
    SignatureCAdES_B(Signer *signer);
    SignatureCAdES_B(const std::vector<unsigned char> &data);
    virtual ~SignatureCAdES_B();

    virtual std::string claimedSigningTime() const override;
    X509Cert signingCertificate() const override;
    std::string signatureMethod() const override;
    virtual void validate() const override final;
    virtual void validate(const std::string &policy) const override;

    void sign();
    operator std::vector<unsigned char>() const;

private:
    DISABLE_COPY(SignatureCAdES_B);

    SignatureCAdESPrivate *d;
    friend SignatureCAdES_T;
};

}
