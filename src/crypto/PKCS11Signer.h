// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "Signer.h"

namespace digidoc
{
    class DIGIDOCPP_EXPORT PKCS11Signer : public Signer
    {

      public:
          PKCS11Signer(const std::string& driver = "");
          ~PKCS11Signer() override;

          X509Cert cert() const override;
          std::string method() const override;
          std::vector<unsigned char> sign(const std::string &method, const std::vector<unsigned char> &digest) const override;
          void setPin(const std::string &pin);

      protected:
          virtual std::string pin(const X509Cert &certificate) const;
          virtual X509Cert selectSigningCertificate(const std::vector<X509Cert> &certificates) const;

      private:
          DISABLE_COPY(PKCS11Signer);
          class Private;
          std::unique_ptr<Private> d;
    };
}
