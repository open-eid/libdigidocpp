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

#ifndef RSA_PSS_SALTLEN_DIGEST
#define RSA_PSS_SALTLEN_DIGEST -1
#endif

namespace digidoc
{

#define SCOPE_PTR_FREE(TYPE, DATA, FREE) make_unique_ptr(DATA, FREE)
#define SCOPE_PTR(TYPE, DATA) SCOPE_PTR_FREE(TYPE, DATA, TYPE##_free)
#define SCOPE(TYPE, VAR, DATA) auto VAR = SCOPE_PTR_FREE(TYPE, DATA, TYPE##_free)

template<class T, typename Func>
[[nodiscard]]
inline std::vector<unsigned char> i2d(T *obj, Func func)
{
    std::vector<unsigned char> result;
    if(!obj)
        return result;
    int size = func(obj, nullptr);
    if(size <= 0)
        return result;
    result.resize(size_t(size), 0);
    if(unsigned char *p = result.data(); func(obj, &p) != size)
        result.clear();
    return result;
}

template<class T, typename Func>
[[nodiscard]]
inline std::vector<unsigned char> i2d(const T &obj, Func func)
{
    return i2d(obj.get(), std::forward<Func>(func));
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
                if(ERR_GET_LIB(error) == ERR_R_BIO_LIB &&
#if OPENSSL_VERSION_NUMBER < 0x30000000L
                    ERR_GET_FUNC(error) == BIO_F_BIO_LOOKUP_EX &&
#endif
                    ERR_GET_REASON(error) == ERR_R_SYS_LIB)
                    e.setCode(ExceptionCode::HostNotFound);
#endif
                addCause(e);
            }
        }
};

#define THROW_OPENSSLEXCEPTION(...) throw OpenSSLException(EXCEPTION_PARAMS(__VA_ARGS__))

}
