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

#include "util/memory.h"

#include <string>
#include <vector>

using PKCS7 = struct pkcs7_st;
using CMS_ContentInfo = struct CMS_ContentInfo_st;
namespace digidoc {

class Digest;
class X509Cert;

class TS
{
public:
    TS(const Digest &digest, const std::string &userAgent = {});
    inline TS(const std::vector<unsigned char> &data): TS(data.data(), data.size()) {}
    TS(const unsigned char *data = nullptr, size_t size = 0);

    X509Cert cert() const;
    std::string digestMethod() const;
    std::vector<unsigned char> digestValue() const;
    std::vector<unsigned char> messageImprint() const;
    std::string serial() const;
    tm time() const;
    void verify(const std::vector<unsigned char> &digest);

    operator std::vector<unsigned char>() const;

private:
    auto tstInfo() const;
    unique_free_t<PKCS7> d;
    unique_free_t<CMS_ContentInfo> cms;
};

}
