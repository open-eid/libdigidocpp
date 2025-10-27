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

#include "Exception.h"
#include "util/log.h"
#include "util/memory.h"

#include <openssl/err.h>

namespace digidoc
{

template<auto F, class T>
[[nodiscard]]
inline std::vector<unsigned char> i2d(T *obj)
{
    std::vector<unsigned char> result;
    if(!obj)
        return result;
    int size = F(obj, nullptr);
    if(size <= 0)
        return result;
    result.resize(size_t(size), 0);
    if(unsigned char *p = result.data(); F(obj, &p) != size)
        result.clear();
    return result;
}

template<auto F, class T>
[[nodiscard]]
inline std::vector<unsigned char> i2d(const T &obj)
{
    return i2d<F>(obj.get());
}

template<auto F, auto D, class C>
constexpr auto d2i(const C &c)
{
    const unsigned char *p = c.data();
    return make_unique_ptr<D>(F(nullptr, &p, long(c.size())));
}

/**
 * OpenSSL exception implementation. Thrown if the openssl returns error
 */
class OpenSSLException : public Exception
{
    public:
        OpenSSLException(const std::string &file, int line, const std::string &msg, unsigned long error = ERR_get_error())
            : Exception(file, line, msg)
        {
            for(; error != 0; error = ERR_get_error())
            {
                Exception e(ERR_lib_error_string(error), 0, ERR_error_string(error, nullptr));
#ifndef LIBRESSL_VERSION_NUMBER
                if(ERR_GET_LIB(error) == ERR_R_BIO_LIB && ERR_GET_REASON(error) == ERR_R_SYS_LIB)
                    e.setCode(ExceptionCode::HostNotFound);
#endif
                addCause(e);
            }
        }
};

#define THROW_OPENSSLEXCEPTION(...) throw OpenSSLException(EXCEPTION_PARAMS(__VA_ARGS__))

}
