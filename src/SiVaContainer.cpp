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

/*
 * Validation Service
 * http://open-eid.github.io/SiVa/
 */

#include "SiVaContainer.h"

#include "Conf.h"
#include "DataFile_p.h"
#include "Signature.h"
#include "crypto/Connect.h"
#include "crypto/Digest.h"
#include "util/File.h"
#include "util/log.h"
#include "xml/xml.hxx"
#include "xml/SecureDOMParser.h"

#include "json.hpp"

#include <xercesc/dom/DOM.hpp>
#include <xercesc/framework/MemBufFormatTarget.hpp>
#include <xercesc/util/Base64.hpp>

#define XSD_CXX11
#include <xsd/cxx/xml/string.hxx>
#include <xsd/cxx/xml/dom/serialization-source.hxx>

#include <algorithm>
#include <fstream>

using namespace digidoc;
using namespace digidoc::util;
using namespace std;
using namespace xercesc;
using json = nlohmann::json;

static std::string base64_decode(const XMLCh *in) {
    static constexpr std::array<std::uint8_t, 128> T{
        0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
        0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
        0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x3E, 0x64, 0x64, 0x64, 0x3F,
        0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
        0x64, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x64, 0x64, 0x64, 0x64, 0x64,
        0x64, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x64, 0x64, 0x64, 0x64, 0x64
    };

    std::string out;
    int value = 0;
    int bits = -8;
    for(; in; ++in)
    {
        const char c(*in);
        if(c == '\r' || c == '\n' || c == ' ')
            continue;
        uint8_t check = T[c];
        if(check == 0x64)
            break;
        value = (value << 6) + check;
        if((bits += 6) < 0)
            continue;
        out.push_back(char((value >> bits) & 0xFF));
        bits -= 8;
    }
    return out;
}



class SiVaContainer::Private
{
public:
    string path, mediaType;
    unique_ptr<istream> ddoc;
    vector<DataFile*> dataFiles;
    vector<Signature*> signatures;
};

vector<unsigned char> SignatureSiVa::dataToSign() const
{
    THROW("Not implemented.");
}

void SignatureSiVa::setSignatureValue(const vector<unsigned char> & /*signatureValue*/)
{
    THROW("Not implemented.");
}

void SignatureSiVa::validate() const
{
    validate(POLv2);
}

void SignatureSiVa::validate(const string &policy) const
{
    static const set<string_view> QES = { "QESIG", "QES", "QESEAL",
        "ADESEAL_QC", "ADESEAL" }; // Special treamtent for E-Seals
    Exception e(EXCEPTION_PARAMS("Signature validation"));
    for(const Exception &exception: _exceptions)
        e.addCause(exception);
    if(!Exception::hasWarningIgnore(Exception::SignatureDigestWeak) &&
        (_signatureMethod == URI_RSA_SHA1 || _signatureMethod == URI_ECDSA_SHA1))
    {
        Exception ex(EXCEPTION_PARAMS("Signature digest weak"));
        ex.setCode(Exception::SignatureDigestWeak);
        e.addCause(ex);
    }
    if(_indication == "TOTAL-PASSED")
    {
        if(QES.count(_signatureLevel) || _signatureLevel.empty() || policy == POLv1)
        {
            if(!e.causes().empty())
                throw e;
            return;
        }
        Exception ex(EXCEPTION_PARAMS("Signing certificate does not meet Qualification requirements"));
        ex.setCode(Exception::CertificateIssuerMissing);
        e.addCause(ex);
    }
    if(!e.causes().empty())
        throw e;
}


SiVaContainer::SiVaContainer(const string &path, const string &ext, bool useHashCode)
    : d(make_unique<Private>())
{
    DEBUG("SiVaContainer::SiVaContainer(%s, %s, %d)", path.c_str(), ext.c_str(), useHashCode);
    unique_ptr<istream> ifs = make_unique<ifstream>(File::encodeName(d->path = path), ifstream::binary);
    auto fileName = File::fileName(path);
    istream *is = ifs.get();
    if(ext == "ddoc")
    {
        d->mediaType = "application/x-ddoc";
        d->ddoc = move(ifs);
        ifs = parseDDoc(useHashCode);
        is = ifs.get();
    }
    else
    {
        d->mediaType = "application/pdf";
        d->dataFiles.push_back(new DataFilePrivate(move(ifs), fileName, "application/pdf"));
    }

    array<XMLByte, 48*100> buf{};
    string b64;
    is->clear();
    is->seekg(0);
    while(*is)
    {
        is->read((char*)buf.data(), buf.size());
        if(is->gcount() <= 0)
            break;

        XMLSize_t size = 0;
        XMLByte *out = Base64::encode(buf.data(), XMLSize_t(is->gcount()), &size);
        if(out)
            b64.append((char*)out, size);
        delete out;
    }
    ifs.reset();

    string req = json({
        {"filename", fileName},
        {"document", move(b64)},
        {"signaturePolicy", "POLv4"}
    }).dump();
    Connect::Result r = Connect(CONF(verifyServiceUri), "POST", 0, {}, CONF(verifyServiceCerts)).exec({
        {"Content-Type", "application/json;charset=UTF-8"}
    }, (const unsigned char*)req.c_str(), req.size());

    if(!r.isOK() && !r.isStatusCode("400"))
        THROW("Failed to send request to SiVa");

    json result = json::parse(r.content, nullptr, false);
    if(result.is_discarded())
        THROW("Failed to parse to SiVa response");

    if(result.contains("requestErrors"))
    {
        Exception e(EXCEPTION_PARAMS("Signature validation"));
        for(const json &error: result["requestErrors"])
            EXCEPTION_ADD(e, "%s", error.value<string>("message", {}).data());
        throw e;
    }

    for(const json &signature: result["validationReport"]["validationConclusion"]["signatures"])
    {
        auto s = unique_ptr<SignatureSiVa>(new SignatureSiVa);
        s->_id = signature["id"];
        s->_signingTime = signature["claimedSigningTime"];
        s->_profile = signature["signatureFormat"];
        s->_indication = signature["indication"];
        s->_subIndication = signature.value<string>("subIndication", {});
        s->_signedBy = signature["signedBy"];
        s->_signatureMethod = signature.value<string>("signatureMethod", {});
        s->_signatureLevel = signature.value<string>("signatureLevel", {});
        if(json info = signature.value<json>("info", {}); !info.is_null())
        {
            s->_bestTime = info.value<string>("bestSignatureTime", {});
            s->_tsTime = info.value<string>("timestampCreationTime", {});
            s->_ocspTime = info.value<string>("ocspResponseCreationTime", {});
            if(info.contains("timeAssertionMessageImprint"))
            {
                string base64 = info["timeAssertionMessageImprint"];
                XMLSize_t size = 0;
                XMLByte *message = Base64::decode((const XMLByte*)base64.c_str(), &size);
                s->_messageImprint.assign(message, message + size);
                delete message;
            }
            for(const json &signerRole: info.value<json>("signerRole", {}))
                s->_signerRoles.push_back(signerRole["claimedRole"]);
            if(json signatureProductionPlace = info.value<json>("signatureProductionPlace", {}); !signatureProductionPlace.is_null())
            {
                s->_city = signatureProductionPlace.value<string>("city", {});
                s->_stateOrProvince = signatureProductionPlace.value<string>("stateOrProvince", {});
                s->_postalCode = signatureProductionPlace.value<string>("postalCode", {});
                s->_country = signatureProductionPlace.value<string>("countryName", {});
            }
        }
        for(const json &certificate: signature.value<json>("certificates", {}))
        {
            XMLSize_t size = 0;
            XMLByte *der = Base64::decode((const XMLByte*)certificate.value<string_view>("content", {}).data(), &size);
            if(certificate["type"] == "SIGNING")
                s->_signingCertificate = X509Cert(der, size, X509Cert::Der);
            if(certificate["type"] == "REVOCATION")
                s->_ocspCertificate = X509Cert(der, size, X509Cert::Der);
            if(certificate["type"] == "SIGNATURE_TIMESTAMP")
                s->_tsCertificate = X509Cert(der, size, X509Cert::Der);
            if(certificate["type"] == "ARCHIVE_TIMESTAMP")
                s->_tsaCertificate = X509Cert(der, size, X509Cert::Der);
            delete der;
        }
        for(const json &error: signature.value<json>("errors", {}))
        {
            string message = error["content"];
            if(message.find("Bad digest for DataFile") == 0 && useHashCode)
                THROW("%s", message.c_str());
            s->_exceptions.emplace_back(EXCEPTION_PARAMS("%s", message.c_str()));
        }
        for(const json &warning: signature.value<json>("warnings", {}))
        {
            string message = warning["content"];
            Exception ex(EXCEPTION_PARAMS("%s", message.c_str()));
            if(message == "X509IssuerName has none or invalid namespace: null" ||
                message == "X509SerialNumber has none or invalid namespace: null")
                ex.setCode(Exception::IssuerNameSpaceWarning);
            else if(message.find("Bad digest for DataFile") == 0)
                ex.setCode(Exception::DataFileNameSpaceWarning);
            else if(message == "Old and unsupported format: SK-XML version: 1.0")
                continue;
            WARN("%s", message.c_str());
        }
        d->signatures.push_back(s.release());
    }
}

SiVaContainer::~SiVaContainer()
{
    for_each(d->signatures.cbegin(), d->signatures.cend(), default_delete<Signature>());
    for_each(d->dataFiles.cbegin(), d->dataFiles.cend(), default_delete<DataFile>());
}

void SiVaContainer::addDataFile(const string & /*path*/, const string & /*mediaType*/)
{
    THROW("Not supported.");
}

void SiVaContainer::addDataFile(unique_ptr<istream> /*is*/, const string & /*fileName*/, const string & /*mediaType*/)
{
    THROW("Not supported.");
}

void SiVaContainer::addAdESSignature(istream & /*signature*/)
{
    THROW("Not supported.");
}

unique_ptr<Container> SiVaContainer::createInternal(const string & /*path*/)
{
    return {};
}

string SiVaContainer::mediaType() const
{
    return d->mediaType;
}

vector<DataFile *> SiVaContainer::dataFiles() const
{
    return d->dataFiles;
}

unique_ptr<Container> SiVaContainer::openInternal(const string &path)
{
    static const array supported {"pdf", "ddoc"};
    string ext = File::fileExtension(path);
    if(find(supported.cbegin(), supported.cend(), ext) == supported.cend())
        return {};
    try {
        return unique_ptr<Container>(new SiVaContainer(path, ext, true));
    } catch(const Exception &e) {
        if(e.msg().find("Bad digest for DataFile") == 0)
            return unique_ptr<Container>(new SiVaContainer(path, ext, false));
        throw;
    }
}

std::unique_ptr<std::istream> SiVaContainer::parseDDoc(bool useHashCode)
{
    namespace xml = xsd::cxx::xml;
    using cpXMLCh = const XMLCh*;
    try
    {
        unique_ptr<DOMDocument> dom(SecureDOMParser().parseIStream(*d->ddoc));
        DOMNodeList *nodeList = dom->getElementsByTagName(cpXMLCh(u"DataFile"));
        for(XMLSize_t i = 0; i < nodeList->getLength(); ++i)
        {
            DOMElement *item = static_cast<DOMElement*>(nodeList->item(i));
            if(!item)
                continue;

            if(XMLString::compareString(item->getAttribute(cpXMLCh(u"ContentType")), cpXMLCh(u"HASHCODE")) == 0)
                THROW("Currently supports only content types EMBEDDED_BASE64 for DDOC format");
            if(XMLString::compareString(item->getAttribute(cpXMLCh(u"ContentType")), cpXMLCh(u"EMBEDDED_BASE64")) != 0)
                continue;

            if(const XMLCh *b64 = item->getTextContent())
            {
                d->dataFiles.push_back(new DataFilePrivate(make_unique<stringstream>(base64_decode(b64)),
                    xml::transcode<char>(item->getAttribute(cpXMLCh(u"Filename"))),
                    xml::transcode<char>(item->getAttribute(cpXMLCh(u"MimeType"))),
                    xml::transcode<char>(item->getAttribute(cpXMLCh(u"Id")))));
            }

            if(!useHashCode)
                continue;
            Digest calc(URI_SHA1);
            SecureDOMParser::calcDigestOnNode(&calc, "http://www.w3.org/TR/2001/REC-xml-c14n-20010315", dom.get(), item);
            vector<unsigned char> digest = calc.result();
            XMLSize_t size = 0;
            if(XMLByte *out = Base64::encode(digest.data(), XMLSize_t(digest.size()), &size))
            {
                item->setAttribute(cpXMLCh(u"ContentType"), cpXMLCh(u"HASHCODE"));
                item->setAttribute(cpXMLCh(u"DigestType"), cpXMLCh(u"sha1"));
                xml::string outXMLCh(reinterpret_cast<const char*>(out));
                item->setAttribute(cpXMLCh(u"DigestValue"), outXMLCh.c_str());
                item->setTextContent(nullptr);
                delete out;
            }
        }

        DOMImplementation *pImplement = DOMImplementationRegistry::getDOMImplementation(cpXMLCh(u"LS"));
        unique_ptr<DOMLSOutput> pDomLsOutput(pImplement->createLSOutput());
        unique_ptr<DOMLSSerializer> pSerializer(pImplement->createLSSerializer());
        auto result = make_unique<stringstream>();
        xml::dom::ostream_format_target out(*result);
        pDomLsOutput->setByteStream(&out);
        pSerializer->setNewLine(cpXMLCh(u"\n"));
        pSerializer->write(dom.get(), pDomLsOutput.get());
        return result;
    }
    catch(const XMLException& e)
    {
        try {
            string result = xml::transcode<char>(e.getMessage());
            THROW("Failed to parse DDoc XML: %s", result.c_str());
        } catch(const xml::invalid_utf16_string & /* ex */) {
            THROW("Failed to parse DDoc XML.");
        }
    }
    catch(const DOMException& e)
    {
        try {
            string result = xml::transcode<char>(e.getMessage());
            THROW("Failed to parse DDoc XML: %s", result.c_str());
        } catch(const xml::invalid_utf16_string & /* ex */) {
            THROW("Failed to parse DDoc XML.");
        }
    } catch(const xml::invalid_utf16_string & /* ex */) {
        THROW("Failed to parse DDoc XML.");
    }
    catch(const Exception &)
    {
        throw;
    }
    catch(...)
    {
        THROW("Failed to parse DDoc XML.");
    }
}

Signature* SiVaContainer::prepareSignature(Signer * /*signer*/)
{
    THROW("Not implemented.");
}

vector<Signature *> SiVaContainer::signatures() const
{
    return d->signatures;
}

void SiVaContainer::removeDataFile(unsigned int /*index*/)
{
    THROW("Not supported.");
}

void SiVaContainer::removeSignature(unsigned int /*index*/)
{
    THROW("Not implemented.");
}

void SiVaContainer::save(const string &path)
{
    string to = path.empty() ? d->path : path;
    if(d->ddoc)
    {
        d->ddoc->clear();
        d->ddoc->seekg(0);
        if(ofstream out{File::encodeName(to), ofstream::binary})
            out << d->ddoc->rdbuf();
    }
    else
        d->dataFiles[0]->saveAs(to);
}

Signature *SiVaContainer::sign(Signer * /*signer*/)
{
    THROW("Not implemented.");
}
