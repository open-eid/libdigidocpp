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

#include "AdditionalInformationType.h"

#include <xsd/cxx/xml/dom/parsing-source.hxx>
#include <xsd/cxx/xml/dom/serialization-source.hxx>

using namespace digidoc::tsl;
using namespace std;
using namespace xercesc;
using namespace xml_schema;

AdditionalInformationType::AdditionalInformationType()
    : AdditionalInformationTypeBase()
{
}

AdditionalInformationType::AdditionalInformationType(const AdditionalInformationType &x, Flags f, Container *c)
    : AdditionalInformationTypeBase(x, f, c)
{
}

AdditionalInformationType::AdditionalInformationType(const DOMElement &e, Flags f, Container *c)
    : AdditionalInformationTypeBase(e, f, c)
{
    xsd::cxx::xml::dom::parser<char> p(e, true, false);
    for (; p.more_elements (); p.next_element ())
    {
        const DOMElement &i(p.cur_element());
        const xsd::cxx::xml::qualified_name<char> n(xsd::cxx::xml::dom::name<char>(i));
        if(n.name() == "OtherInformation" && n.namespace_() == "http://uri.etsi.org/02231/v2#")
        {
            DOMElement *elem = i.getFirstElementChild();
            const xsd::cxx::xml::qualified_name<char> n2(xsd::cxx::xml::dom::name<char>(*elem));
            if(n2.name() == "MimeType")// && n.namespace_() == "http://uri.etsi.org/02231/v2/additionaltypes#")
                mimeType_ = xsd::cxx::xml::transcode<char>(elem->getTextContent());
            if(n2.name() == "SchemeTerritory")
                schemeTerritory_ = xsd::cxx::xml::transcode<char>(elem->getTextContent());
        }
    }
}

AdditionalInformationType::~AdditionalInformationType()
{
}

AdditionalInformationType* AdditionalInformationType::_clone(Flags f, Container *c) const
{
    return new class AdditionalInformationType(*this, f, c);
}

std::string AdditionalInformationType::mimeType() const
{
    return mimeType_;
}

std::string AdditionalInformationType::schemeTerritory() const
{
    return schemeTerritory_;
}

void digidoc::tsl::operator<< (DOMElement &e, const AdditionalInformationType &i)
{
    e << static_cast<const AdditionalInformationTypeBase&>(i);
}

