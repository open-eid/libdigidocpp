// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "Signer.h"

namespace digidoc
{
    class DIGIDOCPP_EXPORT WinSigner : public Signer
    {

      public:
          WinSigner(const std::string &pin = {}, bool selectFirst = false);
          ~WinSigner() final;
          void setPin(const std::string &pin);
          void setSelectFirst(bool first);
          void setThumbprint(const std::vector<unsigned char> &thumbprint);

      private:
          X509Cert cert() const final;
          std::string method() const final;
          std::vector<unsigned char> sign(const std::string &method, const std::vector<unsigned char> &digest) const final;

          DISABLE_COPY(WinSigner);
          class Private;
          Private *d;
    };
}
