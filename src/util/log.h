// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

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

#define STR_VIEW_FMT(str) int(str.size()), str.data()
#define EXCEPTION_PARAMS(...) __FILE__, __LINE__, digidoc::Log::format(__VA_ARGS__)
#define EXCEPTION_ADD(_main, ...) _main.addCause(digidoc::Exception(EXCEPTION_PARAMS(__VA_ARGS__)))
#define THROW(...) throw digidoc::Exception(EXCEPTION_PARAMS(__VA_ARGS__))
#define THROW_CAUSE(_cause, ...) throw digidoc::Exception(EXCEPTION_PARAMS(__VA_ARGS__), _cause)
