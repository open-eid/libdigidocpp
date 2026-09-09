// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "SignatureXAdES_LT.h"

namespace digidoc
{

class SignatureXAdES_LTA final: public SignatureXAdES_LT
{
public:
    using SignatureXAdES_LT::SignatureXAdES_LT;

    std::vector<TSAInfo> ArchiveTimeStamps() const final;
    void validate(const std::string &policy) const final;
    void extendSignatureProfile(Signer *signer) final;

private:
    DISABLE_COPY(SignatureXAdES_LTA);

    void calcArchiveDigest(const Digest &digest, std::string_view canonicalizationMethod, XMLNode node) const;
};

}
