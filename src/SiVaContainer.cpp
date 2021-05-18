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
#include "log.h"
#include "Signature.h"
#include "crypto/Connect.h"
#include "crypto/Digest.h"
#include "util/File.h"
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
#include <set>

using namespace digidoc;
using namespace digidoc::util;
using namespace std;
using namespace xercesc;
using json = nlohmann::json;

class SiVaContainer::Private
{
public:
    string path;
    unique_ptr<istream> data;
    vector<DataFile*> dataFiles;
    vector<Signature*> signatures;
    string mediaType;
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
    static const set<string> QES = { "QESIG", "QES", "QESEAL",
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
    : d(new Private)
{
    DEBUG("SiVaContainer::SiVaContainer(%s, %s, %d)", path.c_str(), ext.c_str(), useHashCode);
    unique_ptr<istream> ifs(new ifstream(File::encodeName(d->path = path).c_str(), ifstream::binary));
    istream *is = ifs.get();
    if(ext == "DDOC")
    {
        d->mediaType = "application/x-ddoc";
        d->data = move(ifs);
        ifs.reset(parseDDoc(*d->data, useHashCode));
        is = ifs.get();
    }
    else
    {
        d->mediaType = "application/pdf";
        d->dataFiles.push_back(new DataFilePrivate(move(ifs), File::fileName(path), "application/pdf", File::fileName(path)));
    }

    XMLByte buf[48*100];
    string b64;
    is->clear();
    is->seekg(0);
    while(*is)
    {
        is->read((char*)buf, 48*100);
        if(is->gcount() <= 0)
            break;

        XMLSize_t size = 0;
        XMLByte *out = Base64::encode(buf, XMLSize_t(is->gcount()), &size);
        if(out)
            b64.append((char*)out, size);
        delete out;
    }

    string url = CONF(verifyServiceUri);
    string req = json({
        {"filename", File::fileName(path)},
        {"document", move(b64)},
        {"signaturePolicy", "POLv4"}
    }).dump();
    Connect::Result r = Connect(url, "POST", 0, {}, CONF(verifyServiceCerts)).exec({
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
            EXCEPTION_ADD(e, error.value<string>("message", {}).c_str());
        throw e;
    }

    for(const json &signature: result["validationReport"]["validationConclusion"]["signatures"])
    {
        SignatureSiVa *s = new SignatureSiVa;
        s->_id = signature["id"];
        s->_signingTime = signature["claimedSigningTime"];
        s->_profile = signature["signatureFormat"];
        s->_indication = signature["indication"];
        s->_subIndication = signature.value<string>("subIndication", {});
        s->_signedBy = signature["signedBy"];
        s->_signatureMethod = signature.value<string>("signatureMethod", {});
        s->_signatureLevel = signature.value<string>("signatureLevel", {});
        json info = signature.value<json>("info", {});
        if(!info.is_null())
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
            json signatureProductionPlace = info.value<json>("signatureProductionPlace", {});
            if(!signatureProductionPlace.is_null())
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
            XMLByte *der = Base64::decode((const XMLByte*)certificate.value<string>("content", {}).c_str(), &size);
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
                THROW(message.c_str());
            s->_exceptions.emplace_back(EXCEPTION_PARAMS(message.c_str()));
        }
        for(const json &warning: signature.value<json>("warnings", {}))
        {
            string message = warning["content"];
            Exception ex(EXCEPTION_PARAMS(message.c_str()));
            if(message == "X509IssuerName has none or invalid namespace: null" ||
                message == "X509SerialNumber has none or invalid namespace: null")
                ex.setCode(Exception::IssuerNameSpaceWarning);
            else if(message.find("Bad digest for DataFile") == 0)
                ex.setCode(Exception::DataFileNameSpaceWarning);
            else if(message == "Old and unsupported format: SK-XML version: 1.0")
                continue;
            WARN("%s", message.c_str());
        }
        d->signatures.push_back(s);
    }
}

SiVaContainer::~SiVaContainer()
{
    for(const Signature *s: d->signatures)
        delete s;
    for(const DataFile *f: d->dataFiles)
        delete f;
    delete d;
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
    static const set<string> supported = {"PDF", "DDOC"};
    string ext = File::fileExtension(path);
    transform(ext.begin(), ext.end(), ext.begin(), ::toupper);
    if(!supported.count(ext))
        return {};
    try {
        return unique_ptr<Container>(new SiVaContainer(path, ext, true));
    } catch(const Exception &e) {
        if(e.msg().find("Bad digest for DataFile") == 0)
            return unique_ptr<Container>(new SiVaContainer(path, ext, false));
        throw;
    }
}

stringstream* SiVaContainer::parseDDoc(istream &is, bool useHashCode)
{
    auto transcode = [](const XMLCh *chr) {
        return xsd::cxx::xml::transcode<char>(chr);
    };
    try
    {
        using cpXMLCh = const XMLCh*;
        unique_ptr<DOMDocument> dom(SecureDOMParser().parseIStream(is));
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
                XMLSize_t size = 0;
                XMLByte *data = Base64::decodeToXMLByte(b64, &size);
                d->dataFiles.push_back(new DataFilePrivate(unique_ptr<istream>(new stringstream(string((const char*)data, size))),
                    transcode(item->getAttribute(cpXMLCh(u"Filename"))), transcode(item->getAttribute(cpXMLCh(u"MimeType"))), transcode(item->getAttribute(cpXMLCh(u"Id")))));
                delete data;
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
                xsd::cxx::xml::string outXMLCh(reinterpret_cast<const char*>(out));
                item->setAttribute(cpXMLCh(u"DigestValue"), outXMLCh.c_str());
                item->setTextContent(nullptr);
                delete out;
            }
        }

        DOMImplementation *pImplement = DOMImplementationRegistry::getDOMImplementation(cpXMLCh(u"LS"));
        unique_ptr<DOMLSOutput> pDomLsOutput(pImplement->createLSOutput());
        unique_ptr<DOMLSSerializer> pSerializer(pImplement->createLSSerializer());
        unique_ptr<stringstream> result(new stringstream);
        xsd::cxx::xml::dom::ostream_format_target out(*result);
        pDomLsOutput->setByteStream(&out);
        pSerializer->setNewLine(cpXMLCh(u"\n"));
        pSerializer->write(dom.get(), pDomLsOutput.get());
        return result.release();
    }
    catch(const XMLException& e)
    {
        try {
            string result = transcode(e.getMessage());
            THROW("Failed to parse DDoc XML: %s", result.c_str());
        } catch(const xsd::cxx::xml::invalid_utf16_string & /* ex */) {
            THROW("Failed to parse DDoc XML.");
        }
    }
    catch(const DOMException& e)
    {
        try {
            string result = transcode(e.getMessage());
            THROW("Failed to parse DDoc XML: %s", result.c_str());
        } catch(const xsd::cxx::xml::invalid_utf16_string & /* ex */) {
            THROW("Failed to parse DDoc XML.");
        }
    } catch(const xsd::cxx::xml::invalid_utf16_string & /* ex */) {
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
    if(d->data)
    {
        ofstream ofs(File::encodeName(to).c_str(), ofstream::binary);
        d->data->clear();
        d->data->seekg(0);
        ofs << d->data->rdbuf();
        ofs.close();
    }
    else
        d->dataFiles[0]->saveAs(to);
}

Signature *SiVaContainer::sign(Signer * /*signer*/)
{
    THROW("Not implemented.");
}
