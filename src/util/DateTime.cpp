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

#include <sstream>
#include <iomanip>

using namespace digidoc;
using namespace digidoc::util::date;
using namespace std;

tm digidoc::util::date::ASN1TimeToTM(const std::string &date)
{
    const char* t = date.c_str();

    if(date.size() < 12)
        THROW("Date time field value shorter than 12 characters: '%s'", t);
#ifdef _WIN32
    tm time = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };
#else
    tm time = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
#endif

    // Accept only GMT time.
    // XXX: What to do, when the time is not in GMT? The time data does not contain
    // DST value and therefore it is not possible to convert it to GMT time.
    if(t[date.size() - 1] != 'Z')
        THROW("Time value is not in GMT format: '%s'", t);

    for(size_t i = 0; i< date.size() - 1; ++i)
    {
        if ((t[i] > '9' || t[i] < '0') && t[i] != '.')
            THROW("Date time value in incorrect format: '%s'", t);
    }

    // Extract year.
    time.tm_year = ((t[0]-'0')*1000 + (t[1]-'0')*100 + (t[2]-'0')*10 + (t[3]-'0')) - 1900;

    // Extract month.
    time.tm_mon = ((t[4]-'0')*10 + (t[5]-'0')) - 1;
    if(time.tm_mon > 11 || time.tm_mon < 0)
        THROW("Month value incorrect: %d", time.tm_mon + 1);

    // Extract day.
    time.tm_mday = (t[6]-'0')*10 + (t[7]-'0');
    if(time.tm_mday > 31 || time.tm_mday < 1)
        THROW("Day value incorrect: %d", time.tm_mday);

    // Extract hour.
    time.tm_hour = (t[8]-'0')*10 + (t[9]-'0');
    if(time.tm_hour > 23 || time.tm_hour < 0)
        THROW("Hour value incorrect: %d", time.tm_hour);

    // Extract minutes.
    time.tm_min = (t[10]-'0')*10 + (t[11]-'0');
    if(time.tm_min > 59 || time.tm_min < 0)
        THROW("Minutes value incorrect: %d", time.tm_min);

    // Extract seconds.
    time.tm_sec = 0;
    if(date.size() >= 14)
    {
        time.tm_sec = (t[12]-'0')*10 + (t[13]-'0');
        if(time.tm_sec > 59 || time.tm_sec < 0)
            THROW("Seconds value incorrect: %d", time.tm_sec);
    }

    return time;
}

/// Dedicated helper for converting xml-schema-style DateTyme into a Zulu-string.
///
/// @param time GMT time as code-synth xml-schema type.
/// @return a string format of date-time e.g. "2007-12-25T14:06:01Z".
string digidoc::util::date::xsd2string(const xml_schema::DateTime& time)
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

time_t digidoc::util::date::xsd2time_t(const xml_schema::DateTime &time)
{
    struct tm t = {
        int(time.seconds()),
        time.minutes(),
        time.hours(),
        time.day(),
        time.month() - 1,
        time.year() - 1900,
        0,
        0,
        0
#ifndef _WIN32
        ,0
        ,0
#endif
    };
    return mktime(&t);
}

time_t digidoc::util::date::string2time_t(const string &time)
{
    class xsdparse: public xml_schema::DateTime
    {
    public: xsdparse(const string &time) { parse(time); }
    };
    return digidoc::util::date::xsd2time_t(xsdparse(time));
}

xml_schema::DateTime digidoc::util::date::makeDateTime(const struct tm& lt)
{
    return xml_schema::DateTime(
        lt.tm_year + 1900,
        static_cast<unsigned short>( lt.tm_mon + 1 ),
        static_cast<unsigned short>( lt.tm_mday ),
        static_cast<unsigned short>( lt.tm_hour ),
        static_cast<unsigned short>( lt.tm_min ),
        lt.tm_sec,
        0, //zone +0h
        0 ); //zone +0min
}
