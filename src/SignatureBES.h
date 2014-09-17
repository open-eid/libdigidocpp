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

#include "Signature.h"

#include <map>

namespace digidoc
{
    class BDoc;
    class Digest;
    class Signer;
    namespace dsig { class SignatureType; }
    namespace xades { class QualifyingPropertiesType; class SignedSignaturePropertiesType; }
    namespace asic { class XAdESSignaturesType; }

    class SignatureBES : public Signature
    {

      public:
          struct Policy
          {
              const std::string DESCRIPTION, URI;
              const std::vector<unsigned char> SHA1, SHA224, SHA256, SHA384, SHA512;
          };
          static const std::map<std::string,Policy> policylist;

          SignatureBES(unsigned int id, BDoc *bdoc);
          SignatureBES(std::istream &sigdata, BDoc *bdoc);
          virtual ~SignatureBES();

          std::string id() const;
          std::string signingTime() const;
          X509Cert signingCertificate() const;
          std::string signatureMethod() const;
          virtual void validate(Validate params = ValidateFULL) const;
          void setSignatureValue(const std::vector<unsigned char> &signatureValue);
          std::vector<unsigned char> prepareSignedInfo(Signer *singer);

          // Xades properties
          std::string policy() const;
          std::string SPUri() const;
          std::string profile() const;
          std::string city() const;
          std::string stateOrProvince() const;
          std::string postalCode() const;
          std::string countryName() const;
          std::vector<std::string> signerRoles() const;

          void addEPES(const std::string &profile);
          std::string addReference(const std::string& uri, const std::string& digestUri,
            const std::vector<unsigned char> &digestValue, const std::string& type = "");
          void addDataObjectFormat(const std::string& uri, const std::string& mime);

          void saveToXml(std::ostream &os) const;

      protected:
          virtual std::string realTime() const;
          std::vector<unsigned char> getSignatureValue() const;
          xades::QualifyingPropertiesType& qualifyingProperties() const;
          xades::SignedSignaturePropertiesType& getSignedSignatureProperties() const;
          void calcDigestOnNode(Digest* calc, const std::string& ns,
                const std::string& tagName, const std::string &id = "") const;

          static const std::string ASIC_NAMESPACE;
          static const std::string XADES_NAMESPACE;
          static const std::string XADESv141_NAMESPACE;
          dsig::SignatureType *signature;
          asic::XAdESSignaturesType *asicsignature;
          BDoc *bdoc;

      private:
          DISABLE_COPY(SignatureBES);

          void setSigningCertificate(const X509Cert& cert);
          void setSignatureProductionPlace(const std::string &city,
              const std::string &stateOrProvince, const std::string &postalCode, const std::string &countryName);
          void setSignerRoles(const std::vector<std::string>& signerRoles);
          void setSigningTime(const struct tm *signingTime);

          // offline checks
          void checkSignatureValue() const;
          void checkSigningCertificate() const;
          void checkKeyInfo() const;

          std::string sigdata_;
    };
}
