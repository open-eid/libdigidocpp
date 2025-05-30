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

#include "util/memory.h"

#include <set>
#include <string>
#include <vector>

using X509_STORE = struct x509_store_st;
using X509_STORE_CTX = struct x509_store_ctx_st;

namespace digidoc
{
    class X509Cert;
    /**
     * X.509 certificate store interface.
     */
    class X509CertStore
    {
    public:
        using Type = std::set<std::string_view>;
        static const Type CA, TSA, OCSP;

        static X509CertStore* instance();

        void activate(const X509Cert &cert) const;
        std::vector<X509Cert> certs(const Type &type) const;
        X509Cert findIssuer(const X509Cert &cert, const Type &type) const;
        static X509Cert issuerFromAIA(const X509Cert &cert);
        static unique_free_t<X509_STORE> createStore(const Type &type, tm &tm);
        bool verify(const X509Cert &cert, bool noqscd, tm validation_time = {}) const;

    private:
        X509CertStore();
        ~X509CertStore();
        DISABLE_COPY(X509CertStore);

        static int validate(int ok, X509_STORE_CTX *ctx);
        class Private;
        std::unique_ptr<Private> d;
    };
}
