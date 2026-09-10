// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

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
        void update() const;
        bool verify(const X509Cert &cert, bool noqscd, tm validation_time = {}) const;

    private:
        X509CertStore();
        ~X509CertStore() noexcept;
        DISABLE_COPY(X509CertStore);

        static int validate(int ok, X509_STORE_CTX *ctx);
        struct Private;
        std::unique_ptr<Private> d;
    };
}
