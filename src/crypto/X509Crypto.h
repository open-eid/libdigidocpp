// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "X509Cert.h"

namespace digidoc
{
    class X509Crypto
    {

      public:
          X509Crypto(X509Cert cert);

          bool compareIssuerToDer(const std::vector<unsigned char> &issuer) const;
          int compareIssuerToString(std::string_view name) const;
          bool isRSAKey() const;

      private:
          X509Cert cert;
    };
}
