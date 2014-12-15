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

typedef struct x509_st X509;

namespace digidoc
{
    class EXP_DIGIDOC X509Cert
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

          explicit X509Cert(X509* cert = 0);
          explicit X509Cert(const unsigned char *bytes, size_t size, Format format = Der);
          explicit X509Cert(const std::vector<unsigned char> &bytes, Format format = Der);
          explicit X509Cert(const std::string &path, Format format = Pem);
          X509Cert(X509Cert &&other);
          X509Cert(const X509Cert &other);
          ~X509Cert();

          std::string serial() const;
          std::string issuerName(const std::string &obj = std::string()) const;
          std::string subjectName(const std::string &obj = std::string()) const;
          std::vector<KeyUsage> keyUsage() const;
          std::vector<std::string> certificatePolicies() const;
          bool isValid(time_t *t = 0) const;

          X509* handle() const;
          operator std::vector<unsigned char>() const;
          X509Cert& operator=(const X509Cert &other);
          X509Cert& operator=(X509Cert &&other);
          bool operator !() const;
          bool operator ==(const X509Cert &other) const;
          bool operator !=(const X509Cert &other) const;

      private:
          std::shared_ptr<X509> cert;
    };
}
