// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "crypto/X509Cert.h"
#include "util/memory.h"

#include <map>
#include <memory>
#include <string>
#include <vector>

using BIO = struct bio_st;
using SSL_CTX = struct ssl_ctx_st;

namespace digidoc {

class Connect
{
public:
    struct Result {
        std::string result, content;
        std::map<std::string,std::string> headers;
        operator bool() const noexcept
        {
            return isOK();
        }
        template<class T>
        inline bool isStatusCode(T code) const noexcept
        {
            return result.find(std::forward<T>(code)) != std::string::npos;
        }
        bool isOK() const noexcept
        {
            return isStatusCode("200");
        }
        bool isRedirect() const noexcept
        {
            return isStatusCode("301") || isStatusCode("302");
        }
        bool isForbidden() const noexcept
        {
            return isStatusCode("403");
        }
    };

    Connect(const std::string &url, std::string_view method = "POST",
        int timeout = 0, std::vector<X509Cert> certs = {}, std::string userAgentData = {},
        std::string_view version = "1.1");
    inline Result exec(std::initializer_list<std::pair<std::string_view,std::string_view>> headers,
        const std::vector<unsigned char> &data)
    {
        return exec(headers, data.data(), data.size());
    }
    Result exec(std::initializer_list<std::pair<std::string_view,std::string_view>> headers = {},
        const unsigned char *data = nullptr, size_t size = 0);

private:
    DISABLE_COPY(Connect);

    Connect(const std::string &url, std::string_view method, int timeout, std::vector<X509Cert> certs,
        std::string userAgentData, std::string_view version, unique_free_t<SSL_CTX> ssl);

    void addHeader(std::string_view key, std::string_view value);
    void sendProxyAuth();
    static std::string decompress(const std::string &encoding, const std::string &data) ;

    std::string baseurl, userAgentData;
    std::string_view method, version;
    std::vector<X509Cert> certs;
    unique_free_t<BIO> d;
    unique_free_t<SSL_CTX> ssl;
    int timeout;
    bool doProxyConnect = false;
    int recursive = 0;
};

}
