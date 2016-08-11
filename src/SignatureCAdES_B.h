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
