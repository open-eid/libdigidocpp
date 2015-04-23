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
    class EXP_DIGIDOC Conf
    {

      public:
          Conf();
          virtual ~Conf();
          static void init(Conf *conf);
          static Conf* instance();

          virtual int logLevel() const;
          virtual std::string logFile() const;
          virtual std::string digestUri() const;
          virtual std::string xsdPath() const;
          virtual std::string PKCS11Driver() const;
          virtual std::string ocsp(const std::string &issuer) const;
          DEPRECATED_DIGIDOCPP virtual std::string certsPath() const;
          virtual std::string proxyHost() const;
          virtual std::string proxyPort() const;
          virtual std::string proxyUser() const;
          virtual std::string proxyPass() const;
          virtual std::string PKCS12Cert() const;
          virtual std::string PKCS12Pass() const;
          virtual bool PKCS12Disable() const;
          virtual std::string libdigidocConf() const;
          DEPRECATED_DIGIDOCPP virtual bool bdoc1Supported() const;
          virtual std::string defaultPolicyId() const;

      private:
          DISABLE_COPY(Conf);

          static Conf *INSTANCE;
    };

    class EXP_DIGIDOC ConfV2: public Conf
    {

      public:
          ConfV2();
          virtual ~ConfV2();
          static ConfV2* instance();

          virtual std::string TSUrl() const;

          virtual bool TSLAutoUpdate() const;
          virtual std::string TSLCache() const;
          DEPRECATED_DIGIDOCPP virtual X509Cert TSLCert() const;
          virtual std::string TSLUrl() const;

      private:
          DISABLE_COPY(ConfV2);
    };

    class EXP_DIGIDOC ConfV3: public ConfV2
    {

      public:
          ConfV3();
          virtual ~ConfV3();
          static ConfV3* instance();

          virtual bool TSLAllowExpired() const;
          virtual std::vector<X509Cert> TSLCerts() const;
          virtual bool TSLOnlineDigest() const;
          virtual int TSLTimeOut() const;

      private:
          DISABLE_COPY(ConfV3);
    };

    class EXP_DIGIDOC ConfV4: public ConfV3
    {

      public:
          ConfV4();
          virtual ~ConfV4();
          static ConfV4* instance();

          virtual std::string signatureDigestUri() const;

      private:
          DISABLE_COPY(ConfV4);
    };

#define CONF(method) ConfV4::instance() ? ConfV4::instance()->method() : ConfV4().method()
}
