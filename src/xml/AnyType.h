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

namespace digidoc {
namespace xades {

class AnyType: public AnyTypeBase
{
public:
    using SPURIType = ::xml_schema::Uri;
    using SPURIOptional = ::xsd::cxx::tree::optional<SPURIType>;
    using SPURITraits = ::xsd::cxx::tree::traits<SPURIType, char>;

    const SPURIOptional& sPURI() const;
    void sPURI(const SPURIType &x);

#ifdef SPUSERNOTICE
    using SPUserNoticeType = ::digidoc::xades::SPUserNoticeType;
    using SPUserNoticeOptional = ::xsd::cxx::tree::optional<SPUserNoticeType>;
    using SPUserNoticeTraits = ::xsd::cxx::tree::traits<SPUserNoticeType, char>;

    const SPUserNoticeOptional& sPUserNotice () const;
    void sPUserNotice(const SPUserNoticeType &x);
#endif

    AnyType();
    AnyType(std::string text);
    AnyType(const xercesc::DOMElement& e, xml_schema::Flags f = {}, xml_schema::Container *c = {});
    AnyType(const AnyType& x, xml_schema::Flags f = {}, xml_schema::Container *c = {});

    AnyType* _clone(xml_schema::Flags f = {}, xml_schema::Container *c = {}) const override;

    std::string text() const;

protected:
    SPURIOptional SPURI_;
#ifdef SPUSERNOTICE
    SPUserNoticeOptional SPUserNotice_;
#endif
    std::string text_;
};

void operator<< (xercesc::DOMElement&, const AnyType&);

}
}
