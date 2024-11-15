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

#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/crypto.h>

#include <openssl/evp.h>

#include <memory>
#include <istream>
#include <ostream>

namespace digidoc {

#define VERSION_CHECK(major, minor, patch) (((major)<<16)|((minor)<<8)|(patch))

template<typename> struct unique_xml;
template<class T>
struct unique_xml<void(T *)>
{
    using type = std::unique_ptr<T,void(*)(T *)>;
};

template<typename T>
using unique_xml_t = typename unique_xml<T>::type;

template<class T, typename D>
[[nodiscard]]
constexpr std::unique_ptr<T, D> make_unique_ptr(T *p, D d) noexcept
{
    return {p, std::forward<D>(d)};
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
        if(EVP_DecodeUpdate(ctx.get(), &result[dataPos], &size, (const unsigned char*)sub.data(), int(sub.size())) == -1)
            THROW("Invalid Base64 Binary");
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

    template<class C, typename P>
    constexpr static auto safe(C c, P p) noexcept
    {
        return c ? c->*p : nullptr;
    }

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

    template<class C, typename P>
    constexpr static sv to_string_view(C d, P p) noexcept
    {
        auto str = safe(d, p);
        return str ? sv(sv::const_pointer(str)) : sv();
    }

    template<typename P>
    constexpr auto children(P p, xmlElementType type = XML_ELEMENT_NODE) const noexcept
    {
        return find(safe(d, p), type);
    }

    constexpr sv name() const noexcept
    {
        return to_string_view(d, &T::name);
    }

    constexpr sv ns() const noexcept
    {
        return to_string_view(safe(d, &T::ns), &xmlNs::href);
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
        constexpr sv whitespace {" \n\r\f\t\v"};
        auto *text = children(&value_type::children, XML_TEXT_NODE);
        auto result = to_string_view(text, &std::decay_t<decltype(*text)>::content);
        result.remove_prefix(std::min<size_t>(result.find_first_not_of(whitespace), result.size()));
        return result;
    }

    pointer d{};
};

struct XMLName
{
    std::string_view name {};
    std::string_view ns {};
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
        return {children(&value_type::children)};
    }

    constexpr iterator end() const noexcept
    {
        return {};
    }

    xmlNsPtr addNS(sv href, sv prefix = {}) const noexcept
    {
        return xmlNewNs(d, pcxmlChar(href.data()), prefix.empty() ? nullptr : pcxmlChar(prefix.data()));
    }

    xmlNsPtr searchNS(sv ns) const noexcept
    {
        return xmlSearchNsByHref(nullptr, d, ns.empty() ? nullptr : pcxmlChar(ns.data()));
    }

    void setNS(xmlNsPtr ns)
    {
        xmlSetNs(d, ns);
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

    operator std::vector<unsigned char>()
    {
        return from_base64(operator sv());
    }

    XMLNode& operator=(sv text) noexcept
    {
        if(!d)
            return *this;
        xmlNodeSetContent(d, pcxmlChar(text.data()));
        return *this;
    }

    constexpr XMLNode operator/(sv name) const noexcept
    {
        return find(*begin(), name, ns());
    }

    constexpr XMLNode operator/(const XMLName &name) const noexcept
    {
        return find(*begin(), name.name, name.ns);
    }

    XMLNode operator+(const XMLName &name) const noexcept
    {
        return {xmlNewChild(d, searchNS(name.ns), pcxmlChar(name.name.data()), nullptr)};
    }

    XMLNode operator+(const char *name) const noexcept
    {
        return operator +({name, ns()});
    }

    constexpr sv operator[](const char *name) const noexcept
    {
        return operator [](XMLName{name, {}});
    }

    constexpr sv operator[](const XMLName &n) const noexcept
    {
        return find(XMLElem<xmlAttr>{children(&value_type::properties, XML_ATTRIBUTE_NODE)}, n.name, n.ns);
    }

    constexpr auto operator+(int i) noexcept
    {
        XMLNode c{*this};
        for(; c && i > 0; --i, c++);
        return c;
    }

    XMLNode& operator=(const std::vector<unsigned char> &data)
    {
        operator=(to_base64(data));
        return *this;
    }
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

    XMLDocument(element_type *ptr = {}, const XMLName &n = {}) noexcept
        : std::unique_ptr<element_type, deleter_type>(ptr, xmlFreeDoc)
        , XMLNode{xmlDocGetRootElement(get())}
    {
        if(d && !n.name.empty() && n.name != name() && !n.ns.empty() && n.ns != ns())
            d = {};
    }

    XMLDocument(std::string_view path, const XMLName &n = {}) noexcept
        : XMLDocument(path.empty() ? nullptr : xmlParseFile(path.data()), n)
    {}

    static XMLDocument openStream(std::istream &is, const XMLName &name = {}, bool hugeFile = false)
    {
        auto ctxt = make_unique_ptr(xmlCreateIOParserCtxt(nullptr, nullptr, [](void *context, char *buffer, int len) -> int {
            auto *is = static_cast<std::istream *>(context);
            is->read(buffer, len);
            return is->good() || is->eof() ? int(is->gcount()) : -1;
        }, nullptr, &is, XML_CHAR_ENCODING_NONE), xmlFreeParserCtxt);
        ctxt->linenumbers = 1;
        ctxt->options |= XML_PARSE_NOENT|XML_PARSE_DTDLOAD|XML_PARSE_DTDATTR|XML_PARSE_NONET;
        ctxt->loadsubset |= XML_DETECT_IDS|XML_COMPLETE_ATTRS;
        if(hugeFile)
            ctxt->options |= XML_PARSE_HUGE;
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
                doc.setNS(doc.addNS(href, prefix));
            xmlDocSetRootElement(doc.get(), doc.d);
        }
        return doc;
    }

    void c14n(const Digest &digest, std::string_view algo, XMLNode node)
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
        auto buf = make_unique_ptr(xmlOutputBufferCreateIO([](void *context, const char *buffer, int len) {
            auto *digest = static_cast<Digest *>(context);
            digest->update(pcxmlChar(buffer), size_t(len));
            return len;
        }, nullptr, const_cast<Digest*>(&digest), nullptr), xmlOutputBufferClose);
        int size = xmlC14NExecute(get(), [](void *root, xmlNodePtr node, xmlNodePtr parent) constexpr noexcept {
            if(root == node)
                return 1;
            for(; parent; parent = parent->parent)
            {
                if(root == parent)
                    return 1;
            }
            return 0;
        }, node.d, mode, nullptr, with_comments, buf.get());
        if(size < 0)
            THROW("Failed to canonicalizate input");
    }

    bool save(std::string_view path) const noexcept
    {
        return xmlSaveFormatFileEnc(path.data(), get(), "UTF-8", 0) > 0;
    }

    bool save(std::ostream &os) const noexcept
    {
        auto *buf = xmlOutputBufferCreateIO([](void *context, const char *buffer, int len) {
            auto *os = static_cast<std::ostream *>(context);
            return os->write(buffer, len) ? len : -1;
        }, nullptr, &os, nullptr);
        return xmlSaveFormatFileTo(buf, get(), "UTF-8", 0) > 0;
    }

    void validateSchema(const std::string &schemaPath) const
    {
        auto parser = make_unique_ptr(xmlSchemaNewParserCtxt(schemaPath.c_str()), xmlSchemaFreeParserCtxt);
        if(!parser)
            THROW("Failed to create schema parser context %s", schemaPath.c_str());
        xmlSchemaSetParserErrors(parser.get(), schemaValidationError, schemaValidationWarning, nullptr);
        auto schema = make_unique_ptr(xmlSchemaParse(parser.get()), xmlSchemaFree);
        if(!schema)
            THROW("Failed to parse schema %s", schemaPath.c_str());
        auto validate = make_unique_ptr(xmlSchemaNewValidCtxt(schema.get()), xmlSchemaFreeValidCtxt);
        if(!validate)
            THROW("Failed to create schema validation context %s", schemaPath.c_str());
        Exception e(EXCEPTION_PARAMS("Failed to XML with schema"));
        xmlSchemaSetValidErrors(validate.get(), schemaValidationError, schemaValidationWarning, &e);
        if(xmlSchemaValidateDoc(validate.get(), get()) != 0)
            throw e;
    }

    static bool verifySignature(XMLNode signature, [[maybe_unused]] Exception *e = {}) noexcept
    {
        auto mngr = make_unique_ptr(xmlSecKeysMngrCreate(), xmlSecKeysMngrDestroy);
        if(!mngr)
            return false;
        if(xmlSecCryptoAppDefaultKeysMngrInit(mngr.get()) < 0)
            return false;
        auto ctx = make_unique_ptr(xmlSecDSigCtxCreate(mngr.get()), xmlSecDSigCtxDestroy);
        if(!ctx)
            return false;
        ctx->keyInfoReadCtx.flags |= XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS;
        int result = xmlSecDSigCtxVerify(ctx.get(), signature.d);
#if VERSION_CHECK(XMLSEC_VERSION_MAJOR, XMLSEC_VERSION_MINOR, XMLSEC_VERSION_SUBMINOR) >= VERSION_CHECK(1, 3, 0)
        if(ctx->failureReason == xmlSecDSigFailureReasonReference)
        {
            for(xmlSecSize i = 0; i < xmlSecPtrListGetSize(&(ctx->signedInfoReferences)); ++i)
            {
                auto *ref = xmlSecDSigReferenceCtxPtr(xmlSecPtrListGetItem(&(ctx->signedInfoReferences), i));
                if(ref->status != xmlSecDSigStatusSucceeded)
                {
                    if(e)
                        e->addCause(Exception(EXCEPTION_PARAMS("Failed to validate Reference '%s'", ref->uri)));
                    else
                        WARN("Failed to validate Reference '%s'", ref->uri);
                }
            }
        }
#endif
        if(result < 0)
            return false;
        return ctx->status == xmlSecDSigStatusSucceeded;
    }

    static void schemaValidationError(void *ctx, const char *msg, ...) noexcept
    {
        va_list args{};
        va_start(args, msg);
        std::string m = Log::formatArgList(msg, args);
        va_end(args);
        if(ctx)
        {
            auto *e = static_cast<Exception*>(ctx);
            e->addCause(digidoc::Exception(EXCEPTION_PARAMS("Schema validation error: %s", m.c_str())));
        }
        else
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
