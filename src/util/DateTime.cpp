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

#include "DateTime.h"

#include "log.h"

#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <ctime>

using namespace digidoc::util;
using namespace std;

struct tm date::gmtime(time_t t)
{
    tm tm {};
#ifdef _WIN32
    if(gmtime_s(&tm, &t) != 0)
#else
    if(!gmtime_r(&t, &tm))
#endif
        THROW("Failed to convert time_t to tm");
    return tm;
}

time_t date::mkgmtime(struct tm &t)
{
#ifdef _WIN32
    return _mkgmtime(&t);
#else
    return timegm(&t);
#endif
}

string date::to_string(time_t t)
{
    return to_string(gmtime(t));
}

string date::to_string(const tm &date)
{
    static const tm zero{};
    if(memcmp(&zero, &date, sizeof(zero)) == 0)
        return {};
    string result(20, 0);
    if(strftime(result.data(), result.size() + 1, "%Y-%m-%dT%H:%M:%SZ", &date) == 0)
        return {};
    return result;
}

/// Dedicated helper for converting xml-schema-style DateTyme into a Zulu-string.
///
/// @param time GMT time as code-synth xml-schema type.
/// @return a string format of date-time e.g. "2007-12-25T14:06:01Z".
string date::to_string(const xml_schema::DateTime& time)
{
    stringstream stream;
    stream << setfill('0') << dec
        << setw(4) << time.year() << "-"
        << setw(2) << time.month() << "-"
        << setw(2) << time.day() << "T"
        << setw(2) << time.hours() << ":"
        << setw(2) << time.minutes() << ":"
        << setw(2) << time.seconds() << "Z";
    return stream.str();
}

time_t date::xsd2time_t(const xml_schema::DateTime &xml)
{
    tm t {
        int(xml.seconds()),
        xml.minutes(),
        xml.hours(),
        xml.day(),
        xml.month() - 1,
        xml.year() - 1900,
        0,
        0,
        0,
#ifndef _WIN32
        0,
        nullptr,
#endif
    };
    return mkgmtime(t);
}

xml_schema::DateTime date::makeDateTime(time_t time)
{
    tm lt = gmtime(time);
    return {
        lt.tm_year + 1900,
        static_cast<unsigned short>( lt.tm_mon + 1 ),
        static_cast<unsigned short>( lt.tm_mday ),
        static_cast<unsigned short>( lt.tm_hour ),
        static_cast<unsigned short>( lt.tm_min ),
        double(lt.tm_sec),
        0, //zone +0h
        0, //zone +0min
    };
}
