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

#include "xml/XAdES01903v132-201601.hxx"
#include "xml/XAdES01903v141-201601.hxx"

namespace digidoc {
namespace xadesv141 {
    typedef xades::XAdESTimeStampType ArchiveTimeStampType;
    typedef xsd::cxx::tree::sequence<ArchiveTimeStampType> ArchiveTimeStampSequence;
    typedef xsd::cxx::tree::traits<ArchiveTimeStampType, char> ArchiveTimeStampTraits;

    typedef xsd::cxx::tree::sequence<ValidationDataType> TimeStampValidationData;
    typedef xsd::cxx::tree::traits<ValidationDataType, char> TimeStampValidationDataTraits;
}
namespace xades {

class UnsignedSignaturePropertiesType: public UnsignedSignaturePropertiesTypeBase
{
public:

    UnsignedSignaturePropertiesType();
    UnsignedSignaturePropertiesType(const xercesc::DOMElement &e, xml_schema::Flags f = 0, xml_schema::Container *c = 0);
    UnsignedSignaturePropertiesType(const UnsignedSignaturePropertiesType &x, xml_schema::Flags f = 0, xml_schema::Container *c = 0);
    virtual ~UnsignedSignaturePropertiesType();

    virtual UnsignedSignaturePropertiesType* _clone(xml_schema::Flags f = 0, xml_schema::Container *c = 0) const;

    const xadesv141::ArchiveTimeStampSequence& archiveTimeStampV141() const;
    xadesv141::ArchiveTimeStampSequence& archiveTimeStampV141();

    static const ::std::size_t archiveTimeStampV141Id = 14UL;

    const xadesv141::TimeStampValidationData& timeStampValidationData() const;
    xadesv141::TimeStampValidationData& timeStampValidationData();

    static const ::std::size_t timeStampValidationDataId = 15UL;

private:
    xadesv141::ArchiveTimeStampSequence ArchiveTimeStampV141_;
    xadesv141::TimeStampValidationData TimeStampValidationData_;
};

void operator<< (xercesc::DOMElement&, const UnsignedSignaturePropertiesType&);

}
}
