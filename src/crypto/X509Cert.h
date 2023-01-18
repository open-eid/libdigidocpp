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

#include "../Exports.h"

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
          explicit X509Cert(const std::string &path, Format format = Pem);
          X509Cert(X509Cert &&other) DIGIDOCPP_NOEXCEPT;
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

          X509* handle() const;
          operator std::vector<unsigned char>() const;
          X509Cert& operator=(const X509Cert &other);
          X509Cert& operator=(X509Cert &&other) DIGIDOCPP_NOEXCEPT;
          operator bool() const;
          bool operator !() const;
          bool operator ==(X509 *other) const;
          bool operator ==(const X509Cert &other) const;
          bool operator !=(const X509Cert &other) const;

      private:
          std::string toOID(ASN1_OBJECT *obj) const;
          template<typename Func>
          std::string toString(Func func, const std::string &obj) const;
          std::shared_ptr<X509> cert;
    };
}
