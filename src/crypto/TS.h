// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

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
