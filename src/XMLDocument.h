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

#include "util/log.h"

#include <libxml/parser.h>
#include <libxml/xmlschemas.h>

#include <memory>

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
        for(; n; n = n->next)
            if(n->type == type)
                return n;
        return {};
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

    constexpr operator sv() const noexcept
    {
        auto text = find(d ? d->children : nullptr, XML_TEXT_NODE);
        return to_string_view(text ? text->content : nullptr);
    }

    pointer d{};
};

struct XMLNode: public XMLElem<xmlNode>
{
    struct Name_NS {
        sv name, ns;
    };

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
        for(XMLElem<xmlAttr> a{d ? d->properties : nullptr}; a; ++a)
        {
            if(a.name() == name && a.ns() == ns)
                return a;
        }
        return {};
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
};

struct XMLDocument: public unique_xml_t<decltype(xmlFreeDoc)>, public XMLNode
{
    using XMLNode::operator bool;

    XMLDocument(element_type *ptr, std::string_view _name = {}, std::string_view _ns = {}) noexcept
        : std::unique_ptr<element_type, deleter_type>(ptr, xmlFreeDoc)
        , XMLNode{xmlDocGetRootElement(get())}
    {
        if(d && !_name.empty() && _name != name() && !_ns.empty() && _ns != ns())
            d = {};
    }

    XMLDocument(std::string_view path, std::string_view name = {}) noexcept
        : XMLDocument(xmlParseFile(path.data()), name)
    {}

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

    bool save(std::string_view path) const noexcept
    {
        return xmlSaveFormatFileEnc(path.data(), get(), "UTF-8", 1) > 0;
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
