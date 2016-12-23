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
        namespace date
        {
            time_t mkgmtime(struct tm &t);
            tm ASN1TimeToTM(const std::string &date, bool generalizedtime = true);
            time_t ASN1TimeToTime_t(const std::string &date, bool generalizedtime = true);
            std::string ASN1TimeToXSD(const std::string &date, bool generalizedtime = true);
            std::string xsd2string(const xml_schema::DateTime &time);
            time_t string2time_t(const std::string &time);
            time_t xsd2time_t(const xml_schema::DateTime &time);
            xml_schema::DateTime makeDateTime(const struct tm &lt);
            tm httpTimeToTM(const std::string &date);
        }
    }
}
