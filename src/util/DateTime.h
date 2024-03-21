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

#include <ctime>
#include <string>

#include "xml/xmldsig-core-schema.hxx"

namespace digidoc
{
    namespace util
    {
        class date
        {
        public:
            static struct tm gmtime(time_t t);
            static time_t mkgmtime(struct tm &t);
            static std::string to_string(time_t t);
            static std::string to_string(const tm &date);
            static std::string to_string(const xml_schema::DateTime &time);
            static time_t xsd2time_t(const xml_schema::DateTime &time);
            static xml_schema::DateTime makeDateTime(time_t time);
        };
    }
}
