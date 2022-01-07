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
using namespace xsd::cxx::xml::dom;

#ifdef _WIN32
#pragma warning( disable: 4355 )
#endif

UnsignedSignaturePropertiesType::UnsignedSignaturePropertiesType()
    : ArchiveTimeStampV141_(this)
    , TimeStampValidationData_(this)
{
}

UnsignedSignaturePropertiesType::UnsignedSignaturePropertiesType(
        const UnsignedSignaturePropertiesType &x, Flags f, Container *c)
    : UnsignedSignaturePropertiesTypeBase(x, f, c)
    , ArchiveTimeStampV141_(x.ArchiveTimeStampV141_, f, this)
    , TimeStampValidationData_(x.TimeStampValidationData_, f, this)
{
}

UnsignedSignaturePropertiesType::UnsignedSignaturePropertiesType(const DOMElement &e, Flags f, Container *c)
    : UnsignedSignaturePropertiesTypeBase(e, f | Flags::base, c)
    , ArchiveTimeStampV141_(this)
    , TimeStampValidationData_(this)
{
    parser<char> p(e, true, false, true);
    for (; p.more_content(); p.next_content(false))
    {
        parse(p, f);
        if(!p.more_content())
            break;
        const DOMElement &i = p.cur_element();
        const xsd::cxx::xml::qualified_name<char> n = name<char>(i);
        if(n.name() == "ArchiveTimeStamp" && n.namespace_() == "http://uri.etsi.org/01903/v1.4.1#")
        {
            ArchiveTimeStampV141_.push_back(xadesv141::ArchiveTimeStampTraits::create(i, f, this));
            content_order_.push_back(ContentOrderType(archiveTimeStampV141Id, ArchiveTimeStampV141_.size () - 1));
            continue;
        }
        if(n.name() == "TimeStampValidationData" && n.namespace_() == "http://uri.etsi.org/01903/v1.4.1#")
        {
            TimeStampValidationData_.push_back(xadesv141::TimeStampValidationDataTraits::create(i, f, this));
            content_order_.push_back(ContentOrderType(timeStampValidationDataId, TimeStampValidationData_.size () - 1));
            continue;
        }
        break;
    }
}

UnsignedSignaturePropertiesType::~UnsignedSignaturePropertiesType() = default;

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
    const char XADES_NS[] = "http://uri.etsi.org/01903/v1.3.2#";
    const char XADES141_NS[] = "http://uri.etsi.org/01903/v1.4.1#";
    e << static_cast<const Type&>(i);

    for(const UnsignedSignaturePropertiesType::ContentOrderType &b: i.contentOrder())
    {
        switch (b.id)
        {
        case UnsignedSignaturePropertiesType::counterSignatureId:
            create_element("CounterSignature", XADES_NS, e) << i.counterSignature()[b.index];
            continue;
        case UnsignedSignaturePropertiesType::signatureTimeStampId:
            create_element("SignatureTimeStamp", XADES_NS, e) << i.signatureTimeStamp()[b.index];
            continue;
        case UnsignedSignaturePropertiesType::completeCertificateRefsId:
            create_element("CompleteCertificateRefs", XADES_NS, e) << i.completeCertificateRefs()[b.index];
            continue;
        case UnsignedSignaturePropertiesType::completeRevocationRefsId:
            create_element("CompleteRevocationRefs", XADES_NS, e) << i.completeRevocationRefs()[b.index];
            continue;
        case UnsignedSignaturePropertiesType::attributeCertificateRefsId:
            create_element("AttributeCertificateRefs", XADES_NS, e) << i.attributeCertificateRefs()[b.index];
            continue;
        case UnsignedSignaturePropertiesType::attributeRevocationRefsId:
            create_element("AttributeRevocationRefs", XADES_NS, e) << i.attributeRevocationRefs()[b.index];
            continue;
        case UnsignedSignaturePropertiesType::sigAndRefsTimeStampId:
            create_element("SigAndRefsTimeStamp", XADES_NS, e) << i.sigAndRefsTimeStamp()[b.index];
            continue;
        case UnsignedSignaturePropertiesType::refsOnlyTimeStampId:
            create_element("RefsOnlyTimeStamp", XADES_NS, e) << i.refsOnlyTimeStamp()[b.index];
            continue;
        case UnsignedSignaturePropertiesType::certificateValuesId:
            create_element("CertificateValues", XADES_NS, e) << i.certificateValues()[b.index];
            continue;
        case UnsignedSignaturePropertiesType::revocationValuesId:
            create_element("RevocationValues", XADES_NS, e) << i.revocationValues()[b.index];
            continue;
        case UnsignedSignaturePropertiesType::attrAuthoritiesCertValuesId:
            create_element("AttrAuthoritiesCertValues", XADES_NS, e) << i.attrAuthoritiesCertValues()[b.index];
            continue;
        case UnsignedSignaturePropertiesType::attributeRevocationValuesId:
            create_element("AttributeRevocationValues", XADES_NS, e) << i.attributeRevocationValues()[b.index];
            continue;
        case UnsignedSignaturePropertiesType::archiveTimeStampId:
            create_element("ArchiveTimeStamp", XADES_NS, e) << i.archiveTimeStamp()[b.index];
            continue;
        case UnsignedSignaturePropertiesType::archiveTimeStampV141Id:
            create_element("ArchiveTimeStamp", XADES141_NS, e) << i.archiveTimeStampV141()[b.index];
            continue;
        case UnsignedSignaturePropertiesType::timeStampValidationDataId:
            create_element("TimeStampValidationData", XADES141_NS, e) << i.timeStampValidationData()[b.index];
            continue;
        default: break;
        }
        break;
    }

    if(i.id())
        create_attribute("Id", e) << *i.id();
}
