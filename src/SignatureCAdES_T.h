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
