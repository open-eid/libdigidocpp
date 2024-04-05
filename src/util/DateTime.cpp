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

#include <cstring>

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
