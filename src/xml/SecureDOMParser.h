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
    X(const XMLCh *txt): cch(xercesc::XMLString::transcode(txt)) {}
    ~X()
    {
        if(xmlch)
            xercesc::XMLString::release(&xmlch);
        if(cch)
            xercesc::XMLString::release(&cch);
    }
    operator XMLCh*() const { return xmlch; }
    operator char*() const { return cch; }
    std::string toString() const { return std::string(cch); }
    operator std::string() const { return toString(); }
private :
    XMLCh *xmlch = nullptr;
    char *cch = nullptr;
};

class SecureDOMParser: public xercesc::DOMLSParserImpl
{
public:
    SecureDOMParser(const std::string &schema_location = std::string());

    static void calcDigestOnNode(Digest *calc, const std::string &algorithmType,
        xercesc::DOMDocument *doc, xercesc::DOMNode *node);

    virtual void doctypeDecl(const xercesc::DTDElementDecl& root,
               const XMLCh* const             public_id,
               const XMLCh* const             system_id,
               const bool                     has_internal,
               const bool                     has_external);

    std::unique_ptr<xercesc::DOMDocument> parseIStream(std::istream &is);
};

}
