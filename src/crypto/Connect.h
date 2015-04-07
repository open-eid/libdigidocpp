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
        bool isRedirect() const
        {
            return result.find("301") != std::string::npos ||
                   result.find("302") != std::string::npos;
        }
    };

    Connect(const std::string &url, const std::string &method = "POST", int timeout = 0);
    void addHeader(const std::string &key, const std::string &value);
    void addHeaders(std::initializer_list<std::pair<std::string,std::string>> list);
    Result exec(const std::vector<unsigned char> &data = std::vector<unsigned char>());
    Result exec(std::initializer_list<std::pair<std::string,std::string>> list,
        const std::vector<unsigned char> &data);

private:
    std::shared_ptr<BIO> d;
    std::shared_ptr<SSL_CTX> ssl;
    int _timeout;
};

}
