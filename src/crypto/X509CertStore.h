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

#include "X509Cert.h"

#include <set>

typedef struct x509_store_st X509_STORE;
typedef struct x509_store_ctx_st X509_STORE_CTX;

namespace digidoc
{
    /**
     * X.509 certificate store interface.
     */
    class X509CertStore
    {
      public:
          static const std::set<std::string> CA, TSA, OCSP;

          static X509CertStore* instance();

          void activate(const std::string &territory) const;
          std::vector<X509Cert> certs(const std::set<std::string> &type) const;
          X509Cert findIssuer(const X509Cert &cert, const std::set<std::string> &type) const;
          static X509_STORE* createStore(const std::set<std::string> &type, time_t *t = nullptr);
          bool verify(const X509Cert &cert) const;

      private:
          X509CertStore();
          ~X509CertStore();
          DISABLE_COPY(X509CertStore);

          static int validate(int ok, X509_STORE_CTX *ctx, const std::set<std::string> &type);
          class Private;
          Private *d;
    };
}
