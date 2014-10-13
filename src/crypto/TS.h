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

#include "Digest.h"
#include <memory>

typedef struct pkcs7_st PKCS7;
namespace digidoc {

class X509Cert;

class TS
{
public:
    TS(const std::string &url, const Digest &digest, const std::string &useragent = "");
    TS(const std::vector<unsigned char> &data);

    X509Cert cert() const;
    std::string digestMethod() const;
    std::string time() const;
    void verify(const Digest &digest);

    operator std::vector<unsigned char>() const;

private:
    std::shared_ptr<PKCS7> d;
};

}
