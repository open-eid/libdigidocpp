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

#include "SignatureXAdES_LT.h"

namespace digidoc
{

class SignatureXAdES_LTA final: public SignatureXAdES_LT
{
public:
    using SignatureXAdES_LT::SignatureXAdES_LT;

    X509Cert ArchiveTimeStampCertificate() const final;
    std::string ArchiveTimeStampTime() const final;
    void validate(const std::string &policy) const final;
    void extendSignatureProfile(const std::string &profile) final;

private:
    DISABLE_COPY(SignatureXAdES_LTA);

    void calcArchiveDigest(const Digest &digest, std::string_view canonicalizationMethod) const;
    TS tsaFromBase64() const;
};

}
