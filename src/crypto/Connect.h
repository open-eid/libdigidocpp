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
        bool operator !() const
        {
            return !isOK();
        }
        bool isStatusCode(const std::string &code) const
        {
            return result.find(code) != std::string::npos;
        }
        bool isOK() const
        {
            return isStatusCode("200");
        }
        bool isRedirect() const
        {
            return isStatusCode("301") || isStatusCode("302");
        }
        bool isForbidden() const
        {
            return isStatusCode("403");
        }
    };

    Connect(const std::string &url, const std::string &method = "POST",
        int timeout = 0, const std::vector<X509Cert> &certs = {});
    ~Connect();
    Result exec(std::initializer_list<std::pair<std::string,std::string>> headers,
        const std::vector<unsigned char> &data);
    Result exec(std::initializer_list<std::pair<std::string,std::string>> headers = {},
        const unsigned char *data = nullptr, size_t size = 0);

private:
    DISABLE_COPY(Connect);

    void addHeader(const std::string &key, const std::string &value);
    void sendProxyAuth();
    static std::string decompress(const std::string &encoding, const std::string &data) ;
    void waitReadWrite(bool read) const;

    std::string baseurl, _method;
    BIO *d = nullptr;
    std::shared_ptr<SSL_CTX> ssl;
    int _timeout;
    bool doProxyConnect = false;
    int fd = -1;
	int recursive = 0;
};

}
