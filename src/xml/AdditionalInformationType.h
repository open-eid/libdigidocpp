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

#include "xml/ts_119612v020201_201601xsd.hxx"

namespace digidoc {
namespace tsl {

class AdditionalInformationType: public AdditionalInformationTypeBase
{
public:
    AdditionalInformationType();
    AdditionalInformationType(const xercesc::DOMElement &e, xml_schema::Flags f = 0, xml_schema::Container *c = 0);
    AdditionalInformationType(const AdditionalInformationType &x, xml_schema::Flags f = 0, xml_schema::Container *c = 0);
    virtual ~AdditionalInformationType();

    virtual AdditionalInformationType* _clone(xml_schema::Flags f = 0, xml_schema::Container *c = 0) const;

    std::string mimeType() const;
    std::string schemeTerritory() const;

private:
    std::string mimeType_;
    std::string schemeTerritory_;
};

void operator<< (xercesc::DOMElement&, const AdditionalInformationType&);

}
}
