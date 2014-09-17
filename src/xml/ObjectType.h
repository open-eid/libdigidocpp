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

#include "xml/xmldsig-core-schema.hxx"
#include "xml/XAdES.hxx"

namespace digidoc {
namespace dsig {

class ObjectType: public ObjectTypeBase
{
public:
    typedef xades::QualifyingPropertiesType QualifyingPropertiesType;
    typedef xsd::cxx::tree::sequence<QualifyingPropertiesType> QualifyingPropertiesSequence;
    typedef QualifyingPropertiesSequence::iterator QualifyingPropertiesIterator;
    typedef QualifyingPropertiesSequence::const_iterator QualifyingPropertiesConstIterator;
    typedef xsd::cxx::tree::traits<QualifyingPropertiesType, char> QualifyingPropertiesTraits;

    ObjectType();
    ObjectType(const xercesc::DOMElement &e, xml_schema::Flags f = 0, xml_schema::Container *c = 0);
    ObjectType(const ObjectType &x, xml_schema::Flags f = 0, xml_schema::Container *c = 0);
    virtual ~ObjectType();

    virtual ObjectType* _clone(xml_schema::Flags f = 0, xml_schema::Container *c = 0) const;

    const QualifyingPropertiesSequence& qualifyingProperties() const;
    QualifyingPropertiesSequence& qualifyingProperties();

private:
    QualifyingPropertiesSequence QualifyingProperties_;
};

void operator<< (xercesc::DOMElement&, const ObjectType&);

}
}
