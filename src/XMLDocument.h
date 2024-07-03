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

#include "crypto/Digest.h"
#include "util/log.h"

#include <libxml/parser.h>
#include <libxml/xmlschemas.h>
#include <libxml/c14n.h> // needs to be last to workaround old libxml2 errors

#include <openssl/evp.h>

#include <memory>
#include <istream>
#include <ostream>

namespace digidoc {

template<typename> struct unique_xml;
template<class T>
struct unique_xml<void(T *)>
{
    using type = std::unique_ptr<T,void(*)(T *)>;
};

template<typename T>
using unique_xml_t = typename unique_xml<T>::type;

template<class T, typename D>
constexpr std::unique_ptr<T, D> make_unique_ptr(T *p, D d) noexcept
{
    return {p, d};
}

static std::vector<unsigned char> from_base64(std::string_view data)
{
    static constexpr std::string_view whitespace {" \n\r\f\t\v"};
    std::vector<unsigned char> result(EVP_DECODE_LENGTH(data.size()), 0);
    size_t dataPos = 0;
    int size = 0;
    auto ctx = make_unique_ptr(EVP_ENCODE_CTX_new(), EVP_ENCODE_CTX_free);
    EVP_DecodeInit(ctx.get());

    for(auto pos = data.find_first_of(whitespace);
         !data.empty();
         pos = data.find_first_of(whitespace), dataPos += size_t(size))
    {
        auto sub = data.substr(0, pos);
        if(pos == std::string_view::npos)
            data = {};
        else
            data.remove_prefix(pos + 1);
        if(EVP_DecodeUpdate(ctx.get(), &result[dataPos], &size, (const unsigned char*)sub.data(), int(sub.size())) >= 0)
            continue;
        result.clear();
        return result;
    }

    if(EVP_DecodeFinal(ctx.get(), &result[dataPos], &size) == 1)
        result.resize(dataPos + size_t(size));
    else
        result.clear();
    return result;
}

static std::string to_base64(const std::vector<unsigned char> &data)
{
    std::string result(EVP_ENCODE_LENGTH(data.size()), 0);
    auto ctx = make_unique_ptr(EVP_ENCODE_CTX_new(), EVP_ENCODE_CTX_free);
    EVP_EncodeInit(ctx.get());
    int size{};
    if(EVP_EncodeUpdate(ctx.get(), (unsigned char*)result.data(), &size, data.data(), int(data.size())) < 1)
    {
        result.clear();
        return result;
    }
    auto pos = size_t(size);
    EVP_EncodeFinal(ctx.get(), (unsigned char*)&result[pos], &size);
    result.resize(pos + size_t(size));
    return result;
}

template<class T>
struct XMLElem
{
    using value_type = T;
    using pointer = value_type*;
    using sv = std::string_view;
    using pcxmlChar = const xmlChar *;

    template<class C>
    constexpr static C find(C n, xmlElementType type) noexcept
    {
        for(; n && n->type != type; n = n->next);
        return n;
    }

    template<class C>
    constexpr static C find(C n, sv name, sv ns) noexcept
    {
        for(; n && (n.name() != name || n.ns() != ns); ++n);
        return n;
    }

    constexpr static sv to_string_view(const xmlChar *str) noexcept
    {
        return str ? sv(sv::const_pointer(str)) : sv();
    }

    constexpr sv name() const noexcept
    {
        return to_string_view(d ? d->name : nullptr);
    }

    constexpr sv ns() const noexcept
    {
        return to_string_view(d && d->ns ? d->ns->href : nullptr);
    }

    constexpr operator bool() const noexcept
    {
        return bool(d);
    }

    constexpr auto& operator++() noexcept
    {
        d = d ? find(d->next, d->type) : nullptr;
        return *this;
    }

    constexpr auto operator++(int) noexcept
    {
        auto c = *this;
        d = find(operator++(), c.name(), c.ns()).d;
        return c;
    }

    constexpr operator sv() const noexcept
    {
        auto text = find(d ? d->children : nullptr, XML_TEXT_NODE);
        return to_string_view(text ? text->content : nullptr);
    }

    pointer d{};
};

struct XMLNode: public XMLElem<xmlNode>
{
    struct iterator: XMLElem<xmlNode>
    {
        using iterator_category = std::forward_iterator_tag;
        using difference_type   = std::ptrdiff_t;

        constexpr XMLNode operator*() const noexcept { return {d}; }
    };

    constexpr iterator begin() const noexcept
    {
        return {find(d ? d->children : nullptr, XML_ELEMENT_NODE)};
    }

    constexpr iterator end() const noexcept
    {
        return {};
    }

    XMLNode addChild(sv name, sv ns = {}) const noexcept
    {
        return {xmlNewChild(d, searchNS(ns), pcxmlChar(name.data()), nullptr)};
    }

    xmlNsPtr addNS(sv href, sv prefix = {}) const noexcept
    {
        return xmlNewNs(d, pcxmlChar(href.data()), prefix.empty() ? nullptr : pcxmlChar(prefix.data()));
    }

    xmlNsPtr searchNS(sv ns) const noexcept
    {
        return xmlSearchNsByHref(nullptr, d, ns.empty() ? nullptr : pcxmlChar(ns.data()));
    }

    constexpr sv property(sv name, sv ns = {}) const noexcept
    {
        return find(XMLElem<xmlAttr>{d ? d->properties : nullptr}, name, ns);
    }

    void setProperty(sv name, sv value, sv ns) const noexcept
    {
        setProperty(name, value, searchNS(ns));
    }

    void setProperty(sv name, sv value, xmlNsPtr ns = {}) const noexcept
    {
        xmlSetNsProp(d, ns, pcxmlChar(name.data()), pcxmlChar(value.data()));
    }

    static iterator erase(iterator pos) noexcept
    {
        iterator next = pos;
        ++next;
        xmlUnlinkNode(pos.d);
        xmlFreeNode(pos.d);
        return next;
    }

    XMLNode& operator=(sv text) noexcept
    {
        if(!d)
            return *this;
        xmlChar *content = xmlEncodeSpecialChars(d->doc, pcxmlChar(text.data()));
        xmlNodeSetContent(d, content);
        xmlFree(content);
        return *this;
    }

    constexpr XMLNode operator/(sv name) const noexcept
    {
        return find(*begin(), name, ns());
    }
};

struct XMLName
{
    std::string_view name = {};
    std::string_view ns = {};
};

struct XMLDocument: public unique_xml_t<decltype(xmlFreeDoc)>, public XMLNode
{
    static constexpr std::string_view C14D_ID_1_0 {"http://www.w3.org/TR/2001/REC-xml-c14n-20010315"};
    static constexpr std::string_view C14D_ID_1_0_COM {"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"};
    static constexpr std::string_view C14D_ID_1_1 {"http://www.w3.org/2006/12/xml-c14n11"};
    static constexpr std::string_view C14D_ID_1_1_COM {"http://www.w3.org/2006/12/xml-c14n11#WithComments"};
    static constexpr std::string_view C14D_ID_1_0_EXC {"http://www.w3.org/2001/10/xml-exc-c14n#"};
    static constexpr std::string_view C14D_ID_1_0_EXC_COM {"http://www.w3.org/2001/10/xml-exc-c14n#WithComments"};

    using XMLNode::operator bool;

    XMLDocument(element_type *ptr, const XMLName &n = {}) noexcept
        : std::unique_ptr<element_type, deleter_type>(ptr, xmlFreeDoc)
        , XMLNode{xmlDocGetRootElement(get())}
    {
        if(d && !n.name.empty() && n.name != name() && !n.ns.empty() && n.ns != ns())
            d = {};
    }

    XMLDocument(std::string_view path, const XMLName &n = {}) noexcept
        : XMLDocument(xmlParseFile(path.data()), n)
    {}

    static XMLDocument openStream(std::istream &is, const XMLName &name = {}, bool hugeFile = false)
    {
        auto ctxt = make_unique_ptr(xmlCreateIOParserCtxt(nullptr, nullptr, [](void *context, char *buffer, int len) -> int {
            auto *is = static_cast<std::istream *>(context);
            is->read(buffer, len);
            return is->good() || is->eof() ? int(is->gcount()) : -1;
        }, nullptr, &is, XML_CHAR_ENCODING_NONE), xmlFreeParserCtxt);
        ctxt->linenumbers = 1;
        if(hugeFile)
            ctxt->options = XML_PARSE_HUGE;
        auto result = xmlParseDocument(ctxt.get());
        if(result != 0 || !ctxt->wellFormed)
            THROW("%s", ctxt->lastError.message);
        return {ctxt->myDoc, name};
    }

    static XMLDocument create(std::string_view name = {}, std::string_view href = {}, std::string_view prefix = {}) noexcept
    {
        XMLDocument doc(xmlNewDoc(nullptr));
        if(!name.empty())
        {
            doc.d = xmlNewNode(nullptr, pcxmlChar(name.data()));
            if(!href.empty())
                xmlSetNs(doc.d, doc.addNS(href, prefix));
            xmlDocSetRootElement(doc.get(), doc.d);
        }
        return doc;
    }

    void c14n(Digest *digest, std::string_view algo, XMLNode node)
    {
        xmlC14NMode mode = XML_C14N_1_0;
        int with_comments = 0;
        if(algo == C14D_ID_1_0)
            mode = XML_C14N_1_0;
        else if(algo == C14D_ID_1_0_COM)
            with_comments = 1;
        else if(algo == C14D_ID_1_1)
            mode = XML_C14N_1_1;
        else if(algo == C14D_ID_1_1_COM)
        {
            mode = XML_C14N_1_1;
            with_comments = 1;
        }
        else if(algo == C14D_ID_1_0_EXC)
            mode = XML_C14N_EXCLUSIVE_1_0;
        else if(algo == C14D_ID_1_0_EXC_COM)
        {
            mode = XML_C14N_EXCLUSIVE_1_0;
            with_comments = 1;
        }
        else if(!algo.empty())
            THROW("Unsupported canonicalization method '%.*s'", int(algo.size()), algo.data());
        auto *buf = xmlOutputBufferCreateIO([](void *context, const char *buffer, int len) {
            auto *digest = static_cast<Digest *>(context);
            digest->update(pcxmlChar(buffer), size_t(len));
            return len;
        }, nullptr, digest, nullptr);
        int size = xmlC14NExecute(get(), [](void *root, xmlNodePtr node, xmlNodePtr parent) constexpr noexcept {
            if(root == node)
                return 1;
            for(; parent; parent = parent->parent)
            {
                if(root == parent)
                    return 1;
            }
            return 0;
        }, node.d, mode, nullptr, with_comments, buf);
        if(size < 0)
            THROW("Failed to canonicalizate input");
    }

    bool save(std::string_view path) const noexcept
    {
        return xmlSaveFormatFileEnc(path.data(), get(), "UTF-8", 1) > 0;
    }

    bool save(std::ostream &os) const noexcept
    {
        auto *buf = xmlOutputBufferCreateIO([](void *context, const char *buffer, int len) {
            auto *os = static_cast<std::ostream *>(context);
            return os->write(buffer, len) ? len : -1;
        }, nullptr, &os, nullptr);
        return xmlSaveFormatFileTo(buf, get(), "UTF-8", 1) > 0;
    }

    bool validateSchema(const std::string &schemaPath) const noexcept
    {
        auto parser = make_unique_ptr(xmlSchemaNewParserCtxt(schemaPath.c_str()), xmlSchemaFreeParserCtxt);
        if(!parser)
            return false;
        xmlSchemaSetParserErrors(parser.get(), schemaValidationError, schemaValidationWarning, nullptr);
        auto schema = make_unique_ptr(xmlSchemaParse(parser.get()), xmlSchemaFree);
        if(!schema)
            return false;
        auto validate = make_unique_ptr(xmlSchemaNewValidCtxt(schema.get()), xmlSchemaFreeValidCtxt);
        if(!validate)
            return false;
        xmlSchemaSetValidErrors(validate.get(), schemaValidationError, schemaValidationWarning, nullptr);
        return xmlSchemaValidateDoc(validate.get(), get()) == 0;
    }

    static void schemaValidationError(void */*ctx*/, const char *msg, ...) noexcept
    {
        va_list args{};
        va_start(args, msg);
        std::string m = Log::formatArgList(msg, args);
        va_end(args);
        ERR("Schema validation error: %s", m.c_str());
    }

    static void schemaValidationWarning(void */*ctx*/, const char *msg, ...) noexcept
    {
        va_list args{};
        va_start(args, msg);
        std::string m = Log::formatArgList(msg, args);
        va_end(args);
        WARN("Schema validation warning: %s", m.c_str());
    }
};

}
