// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "../Exports.h"

#include <initializer_list>
#include <memory>
#include <string>
#include <vector>

using ASN1_OBJECT = struct asn1_object_st;
using X509 = struct x509_st;

namespace digidoc
{
    class DIGIDOCPP_EXPORT X509Cert
    {

      public:
          enum Format
          {
              Der,
              Pem
          };

          enum KeyUsage
          {
            DigitalSignature = 0,
            NonRepudiation,
            KeyEncipherment,
            DataEncipherment,
            KeyAgreement,
            KeyCertificateSign,
            CRLSign,
            EncipherOnly,
            DecipherOnly
          };

          static const std::string QC_COMPLIANT;
          static const std::string QC_SSCD;
          static const std::string QC_QCP;
          static const std::string QC_QCT;

          static const std::string QC_SYNTAX1;
          static const std::string QC_SYNTAX2;

          static const std::string QCS_NATURAL;
          static const std::string QCS_LEGAL;

          static const std::string QCT_ESIGN;
          static const std::string QCT_ESEAL;
          static const std::string QCT_WEB;

          static const std::string QCP_PUBLIC_WITH_SSCD;
          static const std::string QCP_PUBLIC;

          static const std::string QCP_NATURAL;
          static const std::string QCP_LEGAL;
          static const std::string QCP_NATURAL_QSCD;
          static const std::string QCP_LEGAL_QSCD;
          static const std::string QCP_WEB;

          explicit X509Cert(X509 *cert = nullptr);
          explicit X509Cert(const unsigned char *bytes, size_t size, Format format = Der);
          explicit X509Cert(const std::vector<unsigned char> &bytes, Format format = Der);
          inline explicit X509Cert(std::initializer_list<unsigned char> bytes, Format format = Der)
              : X509Cert(bytes.begin(), bytes.size(), format) {}
          explicit X509Cert(const std::string &path, Format format = Pem);
          X509Cert(X509Cert &&other) noexcept;
          X509Cert(const X509Cert &other);
          ~X509Cert();

          std::string serial() const;
          std::string issuerName(const std::string &obj = std::string()) const;
          std::string subjectName(const std::string &obj = std::string()) const;
          std::vector<KeyUsage> keyUsage() const;
          std::vector<std::string> certificatePolicies() const;
          std::vector<std::string> qcStatements() const;
          bool isCA() const;
          bool isValid(time_t *t = nullptr) const;
          bool verify(bool noqscd, tm validation_time = {}) const;

          X509* handle() const;
          operator std::vector<unsigned char>() const;
          X509Cert& operator=(const X509Cert &other);
          X509Cert& operator=(X509Cert &&other) noexcept;
          operator bool() const;
          bool operator !() const;
          bool operator ==(X509 *other) const;
          bool operator ==(const X509Cert &other) const;
          bool operator !=(const X509Cert &other) const;

      private:
          static std::string toOID(ASN1_OBJECT *obj);
          template<auto Func>
          std::string toString(const std::string &obj) const;
          template<auto Func>
          constexpr auto extension(int nid) const noexcept;
          std::shared_ptr<X509> cert;
    };
}
