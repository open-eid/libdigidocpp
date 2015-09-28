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

#include "Exports.h"

#include <string>
#include <vector>

namespace digidoc
{
    class X509Cert;
    class EXP_DIGIDOC Signature
    {
      public:
          virtual ~Signature();

          // DSig properties
          virtual std::string id() const = 0;
          virtual std::string claimedSigningTime() const = 0;
          virtual std::string trustedSigningTime() const = 0;
          virtual X509Cert signingCertificate() const = 0;
          virtual std::string signatureMethod() const = 0;
          virtual void validate() const = 0;

          // Xades properties
          virtual std::string policy() const;
          virtual std::string SPUri() const;
          virtual std::string profile() const = 0;
          virtual std::string city() const = 0;
          virtual std::string stateOrProvince() const = 0;
          virtual std::string postalCode() const = 0;
          virtual std::string countryName() const = 0;
          virtual std::vector<std::string> signerRoles() const = 0;

          //TM profile properties
          virtual std::string OCSPProducedAt() const;
          virtual X509Cert OCSPCertificate() const;
          virtual std::vector<unsigned char> OCSPNonce() const;

          //TS profile properties
          virtual X509Cert TimeStampCertificate() const;
          virtual std::string TimeStampTime() const;

          //TSA profile properties
          virtual X509Cert ArchiveTimeStampCertificate() const;
          virtual std::string ArchiveTimeStampTime() const;

      private:
          Signature();
          DISABLE_COPY(Signature);

      friend class SignatureBES;
      friend class SignatureDDOC;
    };
}
