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

#include "xml/SecureDOMParser.h"

#include <map>
#include <memory>

namespace digidoc
{
    class ASiContainer;
    class Digest;
    class Signer;
    namespace dsig { class SignatureType; }
    namespace xades { class CertIDType; class DigestAlgAndValueType; class QualifyingPropertiesType; class SignedSignaturePropertiesType; }
    namespace asic { class XAdESSignaturesType; class Document_signatures; }

    class Signatures
    {
    public:
        explicit Signatures();
        Signatures(std::istream &data, ASiContainer *container);
        ~Signatures();

        xercesc::DOMElement* element(std::string_view id) const;
        size_t count() const;
        void reloadDOM();
        void save(std::ostream &os) const;

        static const std::string ASIC_NAMESPACE;
        static const std::string OPENDOCUMENT_NAMESPACE;
        static const std::string XADES_NAMESPACE;
        static const std::string XADESv141_NAMESPACE;

        std::unique_ptr<asic::XAdESSignaturesType> asicsignature;
        std::unique_ptr<asic::Document_signatures> odfsignature;

    private:
        void parseDOM(std::istream &data, const std::string &schema_location = {});

        std::unique_ptr<xercesc::DOMDocument> doc;
    };

    class SignatureXAdES_B : public Signature
    {

      public:
          SignatureXAdES_B(unsigned int id, ASiContainer *bdoc, Signer *signer);
          SignatureXAdES_B(const std::shared_ptr<Signatures> &signatures, size_t i, ASiContainer *container);
          ~SignatureXAdES_B() override;

          std::string id() const override;
          std::string claimedSigningTime() const override;
          std::string trustedSigningTime() const override;
          X509Cert signingCertificate() const override;
          std::string signatureMethod() const override;
          void validate() const final;
          void validate(const std::string &policy) const override;
          std::vector<unsigned char> dataToSign() const override;
          void setSignatureValue(const std::vector<unsigned char> &signatureValue) override;

          // Xades properties
          std::string policy() const override;
          std::string SPUri() const override;
          std::string profile() const override;
          std::string city() const override;
          std::string stateOrProvince() const override;
          std::string streetAddress() const override;
          std::string postalCode() const override;
          std::string countryName() const override;
          std::vector<std::string> signerRoles() const override;

          std::string addReference(const std::string& uri, const std::string& digestUri,
              const std::vector<unsigned char> &digestValue, const std::string& type = {}, const std::string &canon = {});
          void addDataObjectFormat(const std::string& uri, const std::string& mime);

          std::shared_ptr<Signatures> signatures;

      protected:
          std::vector<unsigned char> getSignatureValue() const;
          xades::QualifyingPropertiesType& qualifyingProperties() const;
          xades::SignedSignaturePropertiesType& getSignedSignatureProperties() const;
          void calcDigestOnNode(Digest* calc, std::string_view ns,
              std::u16string_view tagName, std::string_view canonicalizationMethod) const;
          static void checkCertID(const xades::CertIDType &certID, const X509Cert &cert);
          static void checkDigest(const xades::DigestAlgAndValueType &digest, const std::vector<unsigned char> &data);

          dsig::SignatureType *signature {};
          ASiContainer *bdoc {};

      private:
          DISABLE_COPY(SignatureXAdES_B);

          struct Policy
          {
              const std::vector<unsigned char> SHA1, SHA224, SHA256, SHA384, SHA512;
          };
          static const std::map<std::string,Policy> policylist;

          void setKeyInfo(const X509Cert& cert);
          void setSigningCertificate(const X509Cert& cert);
          void setSigningCertificateV2(const X509Cert& cert);
          template<class T>
          void setSignatureProductionPlace(const std::string &city, const std::string &streetAddress,
              const std::string &stateOrProvince, const std::string &postalCode, const std::string &countryName);
          template<class T>
          void setSignerRoles(const std::vector<std::string> &signerRoles);
          void setSigningTime(time_t signingTime);

          // offline checks
          void checkSignatureValue() const;
          void checkSigningCertificate(bool noqscd) const;
          void checkKeyInfo() const;
    };
}
