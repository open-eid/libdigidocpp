// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "Signer.h"

namespace digidoc
{
    class DIGIDOCPP_EXPORT PKCS12Signer : public Signer
    {

      public:
          PKCS12Signer(const std::string &path, const std::string &pass);
          ~PKCS12Signer() override;

          X509Cert cert() const override;
          std::vector<unsigned char> sign(const std::string &method, const std::vector<unsigned char> &digest) const override;

      private:
          DISABLE_COPY(PKCS12Signer);
          class Private;
          std::unique_ptr<Private> d;
    };
}
