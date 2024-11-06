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
    XMLNode unsignedSignatureProperties() const;
    TS TimeStamp() const;

    static TS verifyTS(XMLNode timestamp, Exception &exception,
        std::function<void (const Digest &, std::string_view)> &&calcDigest);

private:
    DISABLE_COPY(SignatureXAdES_T);
};

}
