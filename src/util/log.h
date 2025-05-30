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

#include "../Exception.h"

#include <cstdarg>

namespace digidoc
{
    class Log
    {
    public:
        enum LogType
        {
            ErrorType = 0,
            WarnType,
            InfoType,
            DebugType
        };

        static std::string format(const char *fmt, ...);
        static void out(LogType type, const char *file, unsigned int line, const char *format, ...);
        static void dbgPrintfMemImpl(const char *msg, const unsigned char *data, size_t size, const char *file, int line);
        static std::string formatArgList(const char *fmt, va_list args);
    };
}

#define ERR(...) digidoc::Log::out(digidoc::Log::ErrorType, __FILE__, __LINE__, __VA_ARGS__)
#define WARN(...) digidoc::Log::out(digidoc::Log::WarnType, __FILE__, __LINE__, __VA_ARGS__)
#define INFO(...) digidoc::Log::out(digidoc::Log::InfoType, __FILE__, __LINE__, __VA_ARGS__)
#define DEBUG(...) digidoc::Log::out(digidoc::Log::DebugType, __FILE__, __LINE__, __VA_ARGS__)
#define DEBUGMEM(msg, ptr, size) digidoc::Log::dbgPrintfMemImpl(msg, ptr, size, __FILE__, __LINE__)

#define EXCEPTION_PARAMS(...) __FILE__, __LINE__, digidoc::Log::format(__VA_ARGS__)
#define EXCEPTION_ADD(_main, ...) _main.addCause(digidoc::Exception(EXCEPTION_PARAMS(__VA_ARGS__)))
#define THROW(...) throw digidoc::Exception(EXCEPTION_PARAMS(__VA_ARGS__))
#define THROW_CAUSE(_cause, ...) throw digidoc::Exception(EXCEPTION_PARAMS(__VA_ARGS__), _cause)
