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

#include "SignatureXAdES_T.h"

namespace digidoc
{

class SignatureA: public SignatureXAdES_T
{
public:
    SignatureA(unsigned int id, ASiContainer *bdoc, Signer *signer);
    SignatureA(std::istream &sigdata, ASiContainer *bdoc, bool relaxSchemaValidation = false);
    virtual ~SignatureA();

    X509Cert ArchiveTimeStampCertificate() const override;
    std::string ArchiveTimeStampTime() const override;
    virtual void validate() const override;
    virtual void extendSignatureProfile(const std::string &profile) override;

private:
    DISABLE_COPY(SignatureA);

    void calcArchiveDigest(Digest *digest) const;
    std::vector<unsigned char> tsaBase64() const;
};

}
