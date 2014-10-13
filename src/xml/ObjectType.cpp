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

#include "ObjectType.h"

#include <xsd/cxx/xml/dom/parsing-source.hxx>
#include <xsd/cxx/xml/dom/serialization-source.hxx>

using namespace digidoc::dsig;
using namespace digidoc::xades;
using namespace xercesc;
using namespace xml_schema;

#ifdef _WIN32
#pragma warning( disable: 4355 )
#endif

ObjectType::ObjectType()
    : ObjectTypeBase()
    , QualifyingProperties_(this)
{
}

ObjectType::ObjectType(const ObjectType &x, Flags f, Container *c)
    : ObjectTypeBase(x, f, c)
    , QualifyingProperties_(x.QualifyingProperties_, f, this)
{
}

ObjectType::ObjectType(const DOMElement &e, Flags f, Container *c)
    : ObjectTypeBase(e, f, c)
    , QualifyingProperties_ (this)
{
    xsd::cxx::xml::dom::parser<char> p(e, true, false, true);
    for (; p.more_content(); p.next_content(false))
    {
        const DOMElement &i(p.cur_element());
        const xsd::cxx::xml::qualified_name<char> n(xsd::cxx::xml::dom::name<char>(i));
        if(n.name() == "QualifyingProperties" && n.namespace_() == "http://uri.etsi.org/01903/v1.3.2#")
        {
            QualifyingProperties_.push_back(QualifyingPropertiesTraits::create(i, f, this));
            break;
        }
    }
}

ObjectType::~ObjectType()
{
}

ObjectType* ObjectType::_clone(Flags f, Container *c) const
{
    return new class ObjectType(*this, f, c);
}

ObjectType::QualifyingPropertiesSequence& ObjectType::qualifyingProperties()
{
    return QualifyingProperties_;
}

const ObjectType::QualifyingPropertiesSequence& ObjectType::qualifyingProperties() const
{
    return QualifyingProperties_;
}

void digidoc::dsig::operator<< (DOMElement &e, const ObjectType &i)
{
    e << static_cast<const ObjectTypeBase&>(i);

    for(ObjectType::QualifyingPropertiesConstIterator b = i.qualifyingProperties().begin();
        b != i.qualifyingProperties().end(); ++b)
    {
        DOMElement &s(
            xsd::cxx::xml::dom::create_element("QualifyingProperties", "http://uri.etsi.org/01903/v1.3.2#", e));
        s << *b;
    }
}

