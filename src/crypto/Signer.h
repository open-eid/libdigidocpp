// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "../Exception.h"

#include <memory>

namespace digidoc
{
    class X509Cert;
    class DIGIDOCPP_EXPORT Signer
    {

      public:
          virtual ~Signer();

          virtual X509Cert cert() const = 0;
          virtual std::vector<unsigned char> sign(const std::string &method, const std::vector<unsigned char> &digest) const = 0;
          virtual std::string method() const;
          std::string profile() const;
          std::string userAgent() const;
          bool usingENProfile() const;

          std::string city() const;
          std::string streetAddress() const;
          std::string stateOrProvince() const;
          std::string postalCode() const;
          std::string countryName() const;
          std::vector<std::string> signerRoles() const;
          void setMethod(const std::string &method);
          void setProfile(const std::string &profile);
          void setUserAgent(const std::string &userAgent);
          void setENProfile(bool enable);
          void setSignatureProductionPlace(const std::string &city, const std::string &stateOrProvince,
              const std::string &postalCode, const std::string &countryName);
          void setSignatureProductionPlaceV2(const std::string &city, const std::string &streetAddress,
               const std::string &stateOrProvince, const std::string &postalCode, const std::string &countryName);
          void setSignerRoles(const std::vector<std::string>& signerRoles);

      protected:
          Signer();

      private:
          DISABLE_COPY(Signer);
          class Private;
          std::unique_ptr<Private> d;
    };
}
