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

#include <istream>
#include <vector>

namespace digidoc
{
    namespace util
    {
        namespace asic
        {
            const char* const ASICS_EXTENSION = "asics";
            const char* const ASICS_EXTENSION_ABBR = "scs";
            const char* const ASICE_EXTENSION = "asice";
            const char* const ASICE_EXTENSION_ABBR = "sce";
            const char* const BDOC_EXTENSION = "bdoc";
            const char* const ASICS_MIMETYPE = "application/vnd.etsi.asic-s+zip";
            const char* const ASICE_MIMETYPE = "application/vnd.etsi.asic-s+zip";

            enum ASiCFormat
            {
                Unknown,
                Simple,
                Extended
            };

            std::string readMimetype(std::istream &is);
            bool isTimestampedASiC_S(const std::vector<std::string> &list);
            ASiCFormat detectContainerFormat(const std::string &path);
        }
    }
}
