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

#include "log.h"

#include "../Conf.h"
#include "File.h"

#include <fstream>
#include <iomanip>
#include <iostream>

using namespace digidoc;
using namespace digidoc::util;
using namespace std;

/**
 * Formats string, use same syntax as <code>printf()</code> function.
 * Example implementation from:
 * http://www.senzee5.com/2006/05/c-formatting-stdstring.html
 *
 * @param fmt format of the string. Uses same formating as <code>printf()</code> function.
 * @param ... parameters for the string format.
 * @return returns formatted string.
 */
string Log::format(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    string s = formatArgList(fmt, args);
    va_end(args);
    return s;
}

/**
 * Helper method for string formatting.
 *
 * @param fmt format of the string. Uses same formating as <code>printf()</code> function.
 * @param args parameters for the string format.
 * @return returns formatted string.
 * @see String::format(const char* fmt, ...)
 */
string Log::formatArgList(const char* fmt, va_list args)
{
    if(!fmt)
        return "";
    string result(2048, 0);
    int size = vsnprintf(&result[0], result.size() + 1, fmt, args);
    if(size == -1)
        return {};
    result.resize(size_t(size));
    return result;
}

void Log::out(LogType type, const char *file, unsigned int line, const char *format, ...)
{
    Conf *conf = Conf::instance();
    if(!conf || conf->logLevel() < type)
        return;

    ostream *o = &cout;
    fstream f;
    if(!conf->logFile().empty())
    {
        f.open(File::encodeName(conf->logFile()).c_str(), fstream::out|fstream::app);
        o = &f;
    }
    char outtime[] = "0000-00-00T00:00:00Z";
    time_t t = time(nullptr);
    struct tm tm {};
#ifdef _WIN32
    if(gmtime_s(&tm, &t) == 0)
#else
    if(gmtime_r(&t, &tm) != nullptr)
#endif
        strftime(outtime, sizeof(outtime), "%Y-%m-%dT%TZ", &tm);
    *o << outtime << " ";
    switch(type)
    {
    case ErrorType: *o << "E"; break;
    case WarnType: *o << "W"; break;
    case InfoType: *o << "I"; break;
    case DebugType: *o << "D"; break;
    }
    *o << " [" << File::fileName(file) << ":" << line << "] - ";

    va_list args;
    va_start(args, format);
    *o << formatArgList(format, args).c_str() << "\n";
    va_end(args);
}

void Log::dbgPrintfMemImpl(const char *msg, const void *ptr, size_t size, const char *file, int line)
{
    Conf *conf = Conf::instance();
    if(!conf || conf->logLevel() < DebugType)
        return;

    ostream *o = &cout;
    fstream f;
    if(!conf->logFile().empty())
    {
        f.open(File::encodeName(conf->logFile()).c_str(), fstream::out|fstream::app);
        o = &f;
    }

    const unsigned char *data = (const unsigned char*)ptr;
    *o << "DEBUG [" << File::fileName(file) << ":" << line << "] - " << msg << " { ";
    *o << hex << uppercase << setfill('0');
    for(size_t i = 0; i < size; ++i)
        *o << setw(2) << static_cast<int>(data[i]) << ' ';
    *o << dec << nouppercase << setfill(' ') <<"}:" << size << "\n";
}
