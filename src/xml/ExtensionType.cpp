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

#include "ExtensionType.h"

#include <xsd/cxx/xml/dom/parsing-source.hxx>
#include <xsd/cxx/xml/dom/serialization-source.hxx>

using namespace digidoc::tsl;
using namespace xercesc;
using namespace xml_schema;
using namespace xsd::cxx::xml;
using namespace xsd::cxx::xml::dom;

#ifdef _WIN32
#pragma warning( disable: 4355 )
#endif

ExtensionType::ExtensionType(const CriticalType &x)
    : ExtensionTypeBase(x)
    , ExpiredCertsRevocationInfo_(this)
    , TakenOverByType_(this)
    , QualificationsType_(this)
    , AdditionalServiceInformationType_(this)
{
}

ExtensionType::ExtensionType(const ExtensionType &x, Flags f, Container *c)
    : ExtensionTypeBase(x, f, c)
    , ExpiredCertsRevocationInfo_(x.ExpiredCertsRevocationInfo_, f, this)
    , TakenOverByType_(x.TakenOverByType_, f, this)
    , QualificationsType_(x.QualificationsType_, f, this)
    , AdditionalServiceInformationType_(x.AdditionalServiceInformationType_, f, this)
{
}

ExtensionType::ExtensionType(const DOMElement &e, Flags f, Container *c)
    : ExtensionTypeBase(e, f | Flags::base, c)
    , ExpiredCertsRevocationInfo_(this)
    , TakenOverByType_(this)
    , QualificationsType_(this)
    , AdditionalServiceInformationType_(this)
{
    parser<char> p(e, true, false, true);
    for (; p.more_content(); p.next_content(false))
    {
        const DOMElement &i(p.cur_element());
        const qualified_name<char> n(name<char>(i));

        if(n.name() == "ExpiredCertsRevocationInfo" && n.namespace_() == "http://uri.etsi.org/02231/v2#")
        {
            std::unique_ptr<ExpiredCertsRevocationInfo> r(ExpiredCertsRevocationInfoTraits::create(i, f, this));
            if(!this->ExpiredCertsRevocationInfo_.present())
                this->ExpiredCertsRevocationInfo_.set(std::move(r));
            continue;
        }

        if(n.name() == "TakenOverBy" && n.namespace_() == "http://uri.etsi.org/02231/v2/additionaltypes#")
        {
            std::unique_ptr<TakenOverByType> r(TakenOverByTypeTraits::create(i, f, this));
            if(!this->TakenOverByType_.present())
                this->TakenOverByType_.set(std::move(r));
            continue;
        }

        if(n.name() == "Qualifications" && n.namespace_() == "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#")
        {
            std::unique_ptr<QualificationsType> r(QualificationsTypeTraits::create(i, f, this));
            if(!this->QualificationsType_.present())
                this->QualificationsType_.set(std::move(r));
            continue;
        }

        if(n.name() == "AdditionalServiceInformation" && n.namespace_() == "http://uri.etsi.org/02231/v2#")
        {
            std::unique_ptr<AdditionalServiceInformationType> r(AdditionalServiceInformationTypeTraits::create(i, f, this));
            if(!this->AdditionalServiceInformationType_.present())
                this->AdditionalServiceInformationType_.set(std::move(r));
            continue;
        }

        break;
    }
}

ExtensionType::~ExtensionType() = default;

ExtensionType* ExtensionType::_clone(Flags f, Container *c) const
{
    return new class ExtensionType(*this, f, c);
}

const ExtensionType::ExpiredCertsRevocationInfoOptional& ExtensionType::expiredCertsRevocationInfo() const
{
    return ExpiredCertsRevocationInfo_;
}

const ExtensionType::TakenOverByOptional& ExtensionType::takenOverByType() const
{
    return TakenOverByType_;
}

const ExtensionType::QualificationsOptional& ExtensionType::qualificationsType() const
{
    return QualificationsType_;
}

const ExtensionType::AdditionalServiceInformationOptional& ExtensionType::additionalServiceInformationType() const
{
    return AdditionalServiceInformationType_;
}
