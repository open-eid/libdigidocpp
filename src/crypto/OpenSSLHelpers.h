// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

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
