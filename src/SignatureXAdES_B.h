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

#include "XMLDocument.h"

#include <map>

namespace digidoc
{
    constexpr std::string_view OPENDOCUMENT_NS {"urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0"};
    constexpr std::string_view XADESv141_NS {"http://uri.etsi.org/01903/v1.4.1#"};
    constexpr std::string_view REF_TYPE {"http://uri.etsi.org/01903#SignedProperties"};

    constexpr XMLName QualifyingProperties {"QualifyingProperties", XADES_NS};
    constexpr XMLName CanonicalizationMethod {"CanonicalizationMethod", DSIG_NS};

    class ASiContainer;
    class Signer;
    class Signatures: public XMLDocument
    {
    public:
        explicit Signatures();
        Signatures(std::istream &data, std::string_view mediaType);

        constexpr XMLNode signature() const noexcept
        {
            return (*this)/XMLName{"Signature", DSIG_NS};
        }
    };

    class SignatureXAdES_B : public Signature
    {

      public:
          SignatureXAdES_B(const std::shared_ptr<Signatures> &signatures, unsigned int id, ASiContainer *bdoc, Signer *signer);
          SignatureXAdES_B(const std::shared_ptr<Signatures> &signatures, XMLNode s, ASiContainer *container);
          ~SignatureXAdES_B();

          std::string id() const final;
          std::string claimedSigningTime() const final;
          std::string trustedSigningTime() const override;
          X509Cert signingCertificate() const final;
          std::string signatureMethod() const final;
          void validate() const final;
          void validate(const std::string &policy) const override;
          std::vector<unsigned char> dataToSign() const final;
          void setSignatureValue(const std::vector<unsigned char> &value) final;

          // Xades properties
          std::string policy() const final;
          std::string SPUri() const final;
          std::string profile() const final;
          std::string city() const final;
          std::string stateOrProvince() const final;
          std::string streetAddress() const final;
          std::string postalCode() const final;
          std::string countryName() const final;
          std::vector<std::string> signerRoles() const final;

          std::shared_ptr<Signatures> signatures;

      protected:
          std::string_view canonicalizationMethod() const noexcept;
          constexpr XMLNode signatureValue() const noexcept
          {
              return signature/"SignatureValue";
          }
          constexpr XMLNode qualifyingProperties() const noexcept
          {
              return signature/"Object"/QualifyingProperties;
          }
          constexpr XMLNode signedSignatureProperties() const noexcept;
          static void checkCertID(XMLNode certID, const X509Cert &cert);
          static void checkDigest(XMLNode digest, const std::vector<unsigned char> &data);

          XMLNode signature;
          ASiContainer *bdoc {};

      private:
          DISABLE_COPY(SignatureXAdES_B);

          struct Policy
          {
              const std::vector<unsigned char> SHA1, SHA224, SHA256, SHA384, SHA512;
          };
          static const std::map<std::string_view,Policy> policylist;

          std::string addReference(const std::string& uri, const std::string& digestUri,
              const std::vector<unsigned char> &digestValue, std::string_view type = {}, std::string_view canon = {});
          void addDataObjectFormat(const std::string& uri, const std::string& mime);
          void setSigningCertificate(std::string_view name, const X509Cert& cert);
          void setSignatureProductionPlace(std::string_view name, const std::string &city,
              const std::string &streetAddress, const std::string &stateOrProvince,
              const std::string &postalCode, const std::string &countryName) noexcept;
          void setSignerRoles(std::string_view name, const std::vector<std::string> &signerRoles) noexcept;
          constexpr XMLNode V1orV2(std::string_view v1, std::string_view v2) const noexcept;

          // offline checks
          void checkSigningCertificate(bool noqscd) const;
          void checkKeyInfo() const;
    };
}
