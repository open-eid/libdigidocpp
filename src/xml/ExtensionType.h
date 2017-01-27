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
#include "xml/ts_119612v020101_additionaltypes_xsd.hxx"
#include "xml/ts_119612v020101_sie_xsd.hxx"

namespace digidoc {
namespace tsl {

class ExtensionType: public ExtensionTypeBase
{
public:
    typedef ::xml_schema::DateTime ExpiredCertsRevocationInfo;

    typedef ::xsd::cxx::tree::optional<ExpiredCertsRevocationInfo> ExpiredCertsRevocationInfoOptional;
    typedef ::xsd::cxx::tree::traits<ExpiredCertsRevocationInfo, char> ExpiredCertsRevocationInfoTraits;
    const ExpiredCertsRevocationInfoOptional& expiredCertsRevocationInfo() const;

    typedef ::xsd::cxx::tree::optional<TakenOverByType> TakenOverByOptional;
    typedef ::xsd::cxx::tree::traits<TakenOverByType, char> TakenOverByTypeTraits;
    const TakenOverByOptional& takenOverByType() const;

    typedef ::xsd::cxx::tree::optional<QualificationsType> QualificationsOptional;
    typedef ::xsd::cxx::tree::traits<QualificationsType, char> QualificationsTypeTraits;
    const QualificationsOptional& qualificationsType() const;

    typedef ::xsd::cxx::tree::optional<AdditionalServiceInformationType> AdditionalServiceInformationOptional;
    typedef ::xsd::cxx::tree::traits<AdditionalServiceInformationType, char> AdditionalServiceInformationTypeTraits;
    const AdditionalServiceInformationOptional& additionalServiceInformationType() const;

    ExtensionType(const CriticalType &x);
    ExtensionType(const xercesc::DOMElement& e, xml_schema::Flags f = 0, xml_schema::Container* c = 0);
    ExtensionType(const ExtensionType& x, xml_schema::Flags f = 0, xml_schema::Container* c = 0);
    virtual ~ExtensionType();

    virtual ExtensionType* _clone(xml_schema::Flags f = 0, xml_schema::Container* c = 0) const;

protected:
    ExpiredCertsRevocationInfoOptional ExpiredCertsRevocationInfo_;
    TakenOverByOptional TakenOverByType_;
    QualificationsOptional QualificationsType_;
    AdditionalServiceInformationOptional AdditionalServiceInformationType_;
};

}
}
