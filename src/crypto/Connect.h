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

#include "crypto/X509Cert.h"

#include <map>
#include <memory>
#include <string>
#include <vector>

typedef struct bio_st BIO;
typedef struct ssl_ctx_st SSL_CTX;

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

    Connect(const std::string &url, std::string method = "POST",
        int timeout = 0, const std::vector<X509Cert> &certs = {});
    ~Connect();
    inline Result exec(std::initializer_list<std::pair<std::string_view,std::string_view>> headers,
        const std::vector<unsigned char> &data)
    {
        return exec(headers, data.data(), data.size());
    }
    Result exec(std::initializer_list<std::pair<std::string_view,std::string_view>> headers = {},
        const unsigned char *data = nullptr, size_t size = 0);

private:
    DISABLE_COPY(Connect);

    void addHeader(std::string_view key, std::string_view value);
    void sendProxyAuth();
    static std::string decompress(const std::string &encoding, const std::string &data) ;

    std::string baseurl, method;
    BIO *d = nullptr;
    std::shared_ptr<SSL_CTX> ssl;
    int timeout;
    bool doProxyConnect = false;
    int recursive = 0;
};

}
