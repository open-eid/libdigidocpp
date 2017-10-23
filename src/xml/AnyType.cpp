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

#include "AnyType.h"

#include <xsd/cxx/xml/dom/parsing-source.hxx>
#include <xsd/cxx/xml/dom/serialization-source.hxx>
#include <xsd/cxx/xml/char-utf8.hxx>

using namespace digidoc::xades;
using namespace xercesc;
using namespace xml_schema;
using namespace xsd::cxx::xml;
using namespace xsd::cxx::xml::dom;

#ifdef _WIN32
#pragma warning( disable: 4355 )
#endif

AnyType::AnyType()
    : AnyTypeBase()
    , SPURI_(this)
#ifdef SPUSERNOTICE
    , SPUserNotice_(this)
#endif
{
}

AnyType::AnyType(const std::string &text)
    : AnyTypeBase()
    , SPURI_(this)
#ifdef SPUSERNOTICE
    , SPUserNotice_(this)
#endif
    , text_(text)
{
}

AnyType::AnyType(const AnyType &x, Flags f, Container *c)
    : AnyTypeBase(x, f, c)
    , SPURI_(x.SPURI_, f, this)
#ifdef SPUSERNOTICE
    , SPUserNotice_(x.SPUserNotice_, f, this)
#endif
    , text_(x.text_)
{
}

AnyType::AnyType(const DOMElement &e, Flags f, Container *c)
    : AnyTypeBase(e, f | Flags::base, c)
    , SPURI_(this)
#ifdef SPUSERNOTICE
    , SPUserNotice_(this)
#endif
{
    parser<char> p(e, true, true, true);
    bool isText = false;
    for (; p.more_content(); p.next_content(isText))
    {
        const DOMElement &i(p.cur_element());
        const qualified_name<char> n(name<char>(i));

        if(n.name() == "SPURI" && n.namespace_() == "http://uri.etsi.org/01903/v1.3.2#")
        {
            std::unique_ptr<SPURIType> r(SPURITraits::create(i, f, this));
            if(!this->SPURI_.present())
                this->SPURI_.set(std::move(r));
            isText = false;
            text_.clear();
            continue;
        }

#ifdef SPUSERNOTICE
        if(n.name() == "SPUserNotice" && n.namespace_() == "http://uri.etsi.org/01903/v1.3.2#")
        {
            std::unique_ptr<SPUserNoticeType> r(SPUserNoticeTraits::create(i, f, this));
            if(!this->SPUserNotice_.present())
                this->SPUserNotice_.set(std::move(r);
            continue;
        }
#endif

        if(p.cur_is_text())
        {
            const XMLCh *text = p.cur_text().getWholeText();
            XMLSize_t len = XMLString::stringLen(text);
            text_ = char_utf8_transcoder<char>::to(text, len);
            isText = true;
            continue;
        }

        break;
    }
}

AnyType::~AnyType()
{
}

AnyType* AnyType::_clone(Flags f, Container *c) const
{
    return new class AnyType(*this, f, c);
}

const AnyType::SPURIOptional& AnyType::sPURI() const
{
    return SPURI_;
}

void AnyType::sPURI(const SPURIType &x)
{
    SPURI_ = x;
}

std::string AnyType::text() const
{
    return text_;
}



void digidoc::xades::operator<< (DOMElement &e, const AnyType &i)
{
    e << static_cast<const Type&>(i);

    if(!i.text().empty())
    {
        e << i.text();
    }

    if(i.sPURI())
    {
        DOMElement &s(create_element("SPURI", "http://uri.etsi.org/01903/v1.3.2#", e));
        s << *i.sPURI();
    }

#ifdef SPUSERNOTICE
    if(i.sPUserNotice())
    {
        DOMElement &s(create_element("SPUserNotice", "http://uri.etsi.org/01903/v1.3.2#", e));
        s << *i.sPUserNotice();
    }
#endif
}
