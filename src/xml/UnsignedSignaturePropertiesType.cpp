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

#include "UnsignedSignaturePropertiesType.h"

#include <xsd/cxx/xml/dom/parsing-source.hxx>
#include <xsd/cxx/xml/dom/serialization-source.hxx>

using namespace digidoc;
using namespace digidoc::dsig;
using namespace digidoc::xades;
using namespace xercesc;
using namespace xml_schema;

#ifdef _WIN32
#pragma warning( disable: 4355 )
#endif

UnsignedSignaturePropertiesType::UnsignedSignaturePropertiesType()
    : UnsignedSignaturePropertiesTypeBase()
    , ArchiveTimeStampV141_(Flags(), this)
    , TimeStampValidationData_(Flags(), this)
{
}

UnsignedSignaturePropertiesType::UnsignedSignaturePropertiesType(const UnsignedSignaturePropertiesType &x, Flags f, Container *c)
    : UnsignedSignaturePropertiesTypeBase(x, f, c)
    , ArchiveTimeStampV141_(x.ArchiveTimeStampV141_, f, this)
    , TimeStampValidationData_(x.TimeStampValidationData_, f, this)
{
}

UnsignedSignaturePropertiesType::UnsignedSignaturePropertiesType(const DOMElement &e, Flags f, Container *c)
    : UnsignedSignaturePropertiesTypeBase(e, f, c)
    , ArchiveTimeStampV141_(f, this)
    , TimeStampValidationData_(f, this)
{
    xsd::cxx::xml::dom::parser<char> p(e, true, false);
    for (; p.more_elements (); p.next_element ())
    {
        const DOMElement &i(p.cur_element());
        const xsd::cxx::xml::qualified_name<char> n(xsd::cxx::xml::dom::name<char>(i));
        if(n.name() == "ArchiveTimeStamp" && n.namespace_() == "http://uri.etsi.org/01903/v1.4.1#")
            ArchiveTimeStampV141_.push_back(xadesv141::ArchiveTimeStampTraits::create(i, f, this));
        else if(n.name() == "TimeStampValidationData" && n.namespace_() == "http://uri.etsi.org/01903/v1.4.1#")
            TimeStampValidationData_.push_back(xadesv141::TimeStampValidationDataTraits::create(i, f, this));
    }
}

UnsignedSignaturePropertiesType::~UnsignedSignaturePropertiesType()
{
}

UnsignedSignaturePropertiesType* UnsignedSignaturePropertiesType::_clone(Flags f, Container *c) const
{
    return new class UnsignedSignaturePropertiesType(*this, f, c);
}

xadesv141::ArchiveTimeStampSequence& UnsignedSignaturePropertiesType::archiveTimeStampV141()
{
    return ArchiveTimeStampV141_;
}

const xadesv141::ArchiveTimeStampSequence& UnsignedSignaturePropertiesType::archiveTimeStampV141() const
{
    return ArchiveTimeStampV141_;
}

xadesv141::TimeStampValidationData& UnsignedSignaturePropertiesType::timeStampValidationData()
{
    return TimeStampValidationData_;
}

const xadesv141::TimeStampValidationData& UnsignedSignaturePropertiesType::timeStampValidationData() const
{
    return TimeStampValidationData_;
}

void digidoc::xades::operator<< (DOMElement &e, const UnsignedSignaturePropertiesType &i)
{
    e << static_cast<const UnsignedSignaturePropertiesTypeBase&>(i);

    for(const xadesv141::ArchiveTimeStampType &b: i.archiveTimeStampV141())
    {
        DOMElement &s(
            xsd::cxx::xml::dom::create_element("ArchiveTimeStamp", "http://uri.etsi.org/01903/v1.4.1#", e));
        s << b;
    }
    for(const xadesv141::ValidationDataType &b: i.timeStampValidationData())
    {
        DOMElement &s(
            xsd::cxx::xml::dom::create_element("TimeStampValidationData", "http://uri.etsi.org/01903/v1.4.1#", e));
        s << b;
    }
}
