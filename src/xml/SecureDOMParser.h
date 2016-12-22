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

#include <xercesc/parsers/DOMLSParserImpl.hpp>

#include <memory>
#include <string>

namespace digidoc {
class Digest;

class X
{
public :
    X(const char *txt): xmlch(xercesc::XMLString::transcode(txt)) {}
    X(const std::string &txt): xmlch(xercesc::XMLString::transcode(txt.c_str())) {}
    ~X() { xercesc::XMLString::release(&xmlch); }
    operator XMLCh*() const { return xmlch; }
private :
    XMLCh *xmlch;
};

class SecureDOMParser: public xercesc::DOMLSParserImpl
{
public:
    SecureDOMParser(const std::string &schema_location = std::string());

    virtual void doctypeDecl(const xercesc::DTDElementDecl& root,
               const XMLCh* const             public_id,
               const XMLCh* const             system_id,
               const bool                     has_internal,
               const bool                     has_external);

    std::unique_ptr<xercesc::DOMDocument> parseIStream(std::istream &is);
};

}
