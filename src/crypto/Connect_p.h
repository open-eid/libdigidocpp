// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "Connect.h"

#include "crypto/OpenSSLHelpers.h"

#include <zlib.h>

#include <algorithm>
#include <string_view>

#define THROW_NETWORKEXCEPTION(...) { \
    OpenSSLException ex(EXCEPTION_PARAMS(__VA_ARGS__)); \
    if(ex.code() == Exception::General) \
        ex.setCode(Exception::NetworkError); \
    throw ex; \
}

namespace digidoc
{

constexpr size_t MAX_RESPONSE_SIZE = 10 * 1024 * 1024;

constexpr bool nextLine(std::string_view &remaining, std::string_view &line) noexcept
{
    const auto end = remaining.find('\n');
    if(end == std::string_view::npos)
        return false;
    line = remaining.substr(0, end);
    remaining.remove_prefix(end + 1);
    if(line.ends_with('\r'))
        line.remove_suffix(1);
    return true;
}

constexpr size_t headerEnd(std::string_view data) noexcept
{
    const auto size = data.size();
    for(std::string_view line; nextLine(data, line);)
    {
        if(line.empty())
            return size - data.size();
    }
    return std::string_view::npos;
}

inline std::string decompress(const std::string &encoding, const std::string &data)
{
    if(data.empty())
        return data;

    z_stream s {
        .next_in = (Bytef*)data.c_str(),
        .avail_in = uInt(data.size())
    };
    int result = Z_OK;
    if(encoding == "gzip")
        result = inflateInit2(&s, 16 + MAX_WBITS);
    else if(encoding == "deflate")
        result = inflateInit2(&s, -MAX_WBITS);
    else
    {
        WARN("Unsuported Content-Encoding: %s", encoding.c_str());
        return data;
    }
    if(result != Z_OK) {
        WARN("Failed to uncompress content Content-Encoding: %s", encoding.c_str());
        return data;
    }
    auto stream = make_unique_ptr<inflateEnd>(&s);

    std::string out(2048, 0);
    do {
        if(s.total_out >= out.size()) {
            if(out.size() > MAX_RESPONSE_SIZE)
                THROW_NETWORKEXCEPTION("HTTP decompressed response exceeds maximum allowed size of %zu bytes", MAX_RESPONSE_SIZE)
            out.resize(std::min(out.size() * 2, MAX_RESPONSE_SIZE + 1));
        }
        s.next_out = (Bytef*)&out[s.total_out];
        s.avail_out = uInt(uLong(out.size()) - s.total_out);
        switch(inflate(&s, Z_NO_FLUSH))
        {
        case Z_OK:
        case Z_STREAM_END: break;
        default: THROW_NETWORKEXCEPTION("Failed to decompress HTTP content")
        }
    } while(s.avail_out == 0);
    out.resize(s.total_out);
    return out;
}

}
