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

#include "SecureDOMParser.h"

#include "crypto/Digest.h"
#include "log.h"

DIGIDOCPP_WARNING_PUSH
DIGIDOCPP_WARNING_DISABLE_CLANG("-Wnull-conversion")
DIGIDOCPP_WARNING_DISABLE_GCC("-Wunused-parameter")
DIGIDOCPP_WARNING_DISABLE_MSVC(4005)
#include <xercesc/framework/Wrapper4InputSource.hpp>
#include <xsd/cxx/tree/error-handler.hxx>
#include <xsd/cxx/xml/dom/bits/error-handler-proxy.hxx>
#include <xsd/cxx/xml/sax/std-input-source.hxx>
#include <xsec/canon/XSECC14n20010315.hpp>
#include <xsec/dsig/DSIGReference.hpp>
DIGIDOCPP_WARNING_POP

#include <sstream>

using namespace digidoc;
using namespace std;
using namespace xercesc;
namespace xml = xsd::cxx::xml;

SecureDOMParser::SecureDOMParser(const string &schema_location)
{
    DOMConfiguration *conf = getDomConfig();
    // Discard comment nodes in the document.
    conf->setParameter(XMLUni::fgDOMComments, false);
    // Enable datatype normalization.
    conf->setParameter(XMLUni::fgDOMDatatypeNormalization, true);
    // Do not create EntityReference nodes in the DOM tree. No
    // EntityReference nodes will be created, only the nodes
    // corresponding to their fully expanded substitution text
    // will be created.
    conf->setParameter(XMLUni::fgDOMEntities, false);
    conf->setParameter(XMLUni::fgDOMNamespaces, true);
    conf->setParameter(XMLUni::fgDOMElementContentWhitespace, false);
    // Enable validation.
    conf->setParameter(XMLUni::fgDOMValidate, !schema_location.empty());
    conf->setParameter(XMLUni::fgXercesSchema, !schema_location.empty());
    conf->setParameter(XMLUni::fgXercesSchemaFullChecking, false);
    if(!schema_location.empty())
    {
        xml::string sl(schema_location);
        conf->setParameter(XMLUni::fgXercesSchemaExternalSchemaLocation, sl.c_str());
    }
    // Xerces-C++ 3.1.0 is the first version with working multi import
    // support.
    conf->setParameter(XMLUni::fgXercesHandleMultipleImports, true);
    // We will release the DOM document ourselves.
    conf->setParameter(XMLUni::fgXercesUserAdoptsDOMDocument, true);
}

void SecureDOMParser::calcDigestOnNode(Digest *calc,
    const string &algorithmType, DOMDocument *doc, DOMNode *node)
{
    XSECC14n20010315 c14n(doc, node);
    c14n.setCommentsProcessing(false);
    c14n.setUseNamespaceStack(true);

    // Set processing flags according to algorithm type.
    if(algorithmType == URI_ID_C14N_NOC) {
        // Default behaviour, nothing needs to be changed
    } else if(algorithmType == URI_ID_C14N_COM) {
        c14n.setCommentsProcessing(true);
    } else if(algorithmType == URI_ID_EXC_C14N_NOC) {
        // Exclusive mode needs to include xml-dsig in root element
        // in order to maintain compatibility with existing implementations
        c14n.setExclusive();
    } else if(algorithmType == URI_ID_EXC_C14N_COM) {
        c14n.setExclusive();
        c14n.setCommentsProcessing(true);
    } else if(algorithmType == URI_ID_C14N11_NOC) {
        c14n.setInclusive11();
    } else if(algorithmType == URI_ID_C14N11_COM) {
        c14n.setInclusive11();
        c14n.setCommentsProcessing(true);
    } else {
        THROW("Unsupported canonicalization method '%s'", algorithmType.c_str());
    }

    unsigned char buffer[1024];
    xsecsize_t bytes = 0;
    while((bytes = c14n.outputBuffer(buffer, 1024)) > 0)
        calc->update(buffer, (unsigned int)bytes);
}

void SecureDOMParser::doctypeDecl(const DTDElementDecl& root,
           const XMLCh* const             public_id,
           const XMLCh* const             system_id,
           const bool                     has_internal,
           const bool                     has_external)
{
    if(has_internal || has_external)
        ThrowXMLwithMemMgr(RuntimeException, XMLExcepts::Gen_NoDTDValidator, fMemoryManager);
    DOMLSParserImpl::doctypeDecl(root, public_id, system_id, has_internal, has_external);
}

unique_ptr<DOMDocument> SecureDOMParser::parseIStream(std::istream &is)
{
    // Parse the XML document.
    // Wrap the standard input stream.
    xml::sax::std_input_source isrc(is);
    Wrapper4InputSource wrap(&isrc, false);
    // Set error handler.
    xsd::cxx::tree::error_handler<char> eh;
    xml::dom::bits::error_handler_proxy<char> ehp(eh);
    getDomConfig()->setParameter(XMLUni::fgDOMErrorHandler, &ehp);
    // Parse XML to DOM.
    unique_ptr<DOMDocument> doc(DOMLSParserImpl::parse(&wrap));
    try {
        eh.throw_if_failed<xsd::cxx::tree::parsing<char>>();
    }
    catch(const xsd::cxx::tree::parsing<char> &e)
    {
        stringstream s;
        s << e;
        THROW("Failed to parse XML %s\n%s", e.what(), s.str().c_str());
    }
    return doc;
}
