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
#include "xml/SecureDOMParser.h"

#include "jsonxx.cc"

#include <xercesc/dom/DOM.hpp>
#include <xercesc/framework/MemBufFormatTarget.hpp>
#include <xercesc/util/Base64.hpp>

#include <algorithm>
#include <fstream>
#include <set>

using namespace digidoc;
using namespace digidoc::util;
using namespace std;
using namespace xercesc;

class SiVaContainer::Private
{
public:
    vector<DataFile*> dataFiles;
    vector<Signature*> signatures;
    string mediaType;
};

vector<unsigned char> SignatureSiVa::dataToSign() const
{
    THROW("Not implemented.");
}

void SignatureSiVa::setSignatureValue(const vector<unsigned char> &)
{
    THROW("Not implemented.");
}

void SignatureSiVa::validate() const
{
    validate(POLv2);
}

void SignatureSiVa::validate(const std::string &policy) const
{
    Exception e(EXCEPTION_PARAMS("Signature validation"));
    if(_indication == "TOTAL-PASSED")
    {
        if(_signatureLevel == "QES"|| _signatureLevel.empty() || policy == POLv1)
            return;
        Exception ex(EXCEPTION_PARAMS("Signing certificate does not meet Qualification requirements"));
        ex.setCode(Exception::CertificateIssuerMissing);
        e.addCause(ex);
    }
    else
    {
        for(const Exception &error: _errors)
            e.addCause(error);
    }
    if(!e.causes().empty())
        throw e;
}


SiVaContainer::SiVaContainer(const string &path, const string &ext)
    : d(new Private)
{
    unique_ptr<istream> ifs(new ifstream(File::encodeName(path).c_str(), ifstream::binary));
    istream *is = ifs.get();
    unique_ptr<stringstream> ddoc;
    if(ext == "DDOC")
    {
        d->mediaType = "application/x-ddoc";
        ddoc.reset(parseDDoc(ifs.get()));
        is = ddoc.get();
    }
    else
    {
        d->mediaType = "application/pdf";
        d->dataFiles.push_back(new DataFilePrivate(ifs.release(), File::fileName(path), "application/pdf", File::fileName(path)));
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


    string req = (jsonxx::Object()
        << "filename" << File::fileName(path)
        << "documentType" << ext
        << "document" << b64).json();
    Connect::Result r = Connect(CONF(verifyServiceUri), "POST", 0, "", CONF(verifyServiceCert)).exec({
        {"Content-Type", "application/json;charset=UTF-8"}
    }, vector<unsigned char>(req.c_str(), req.c_str()+req.size()));

    if(!r)
        THROW("Failed to send request to SiVa");

    jsonxx::Object result;
    result.parse(r.content);

    if(result.has<jsonxx::Array>("requestErrors"))
    {
        Exception e(EXCEPTION_PARAMS("Signature validation"));
        for(const jsonxx::Value *error: result.get<jsonxx::Array>("requestErrors").values())
        {
            string message = error->get<jsonxx::Object>().get<string>("message");
            e.addCause(Exception(EXCEPTION_PARAMS(message.c_str())));
        }
        throw e;
    }

    for(const jsonxx::Value *obj: result.get<jsonxx::Array>("signatures").values())
    {
        SignatureSiVa *s = new SignatureSiVa;
        jsonxx::Object signature = obj->get<jsonxx::Object>();
        s->_id = signature.get<string>("id");
        s->_signingTime = signature.get<string>("claimedSigningTime");
        s->_bestTime = signature.get<jsonxx::Object>("info").get<string>("bestSignatureTime");
        s->_profile = signature.get<string>("signatureFormat");
        s->_indication = signature.get<string>("indication");
        s->_subIndication = signature.get<string>("subIndication");
        s->_signedBy = signature.get<string>("signedBy");
        s->_signatureLevel = signature.get<string>("signatureLevel");
        for(const jsonxx::Value *error: signature.get<jsonxx::Array>("errors").values())
        {
            string message = error->get<jsonxx::Object>().get<string>("content");
            s->_errors.push_back(Exception(EXCEPTION_PARAMS(message.c_str())));
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

void SiVaContainer::addDataFile(const string &, const string &)
{
    THROW("Not supported.");
}

void SiVaContainer::addDataFile(istream *, const string &, const string &)
{
    THROW("Not supported.");
}

void SiVaContainer::addAdESSignature(istream &)
{
    THROW("Not supported.");
}

Container* SiVaContainer::createInternal(const string &)
{
    return nullptr;
}

string SiVaContainer::mediaType() const
{
    return d->mediaType;
}

vector<DataFile *> SiVaContainer::dataFiles() const
{
    return d->dataFiles;
}

Container* SiVaContainer::openInternal(const string &path)
{
    static set<string> supported = {"PDF", "DDOC"};
    string ext = File::fileExtension(path);
    transform(ext.begin(), ext.end(), ext.begin(), ::toupper);
    return supported.find(ext) != supported.cend() ? new SiVaContainer(path, ext) : nullptr;
}

std::stringstream* SiVaContainer::parseDDoc(std::istream *is)
{
    try
    {
        unique_ptr<DOMDocument> dom(SecureDOMParser().parseIStream(*is));
        DOMNodeList *nodeList = dom->getElementsByTagNameNS(X("http://www.sk.ee/DigiDoc/v1.3.0#"), X("DataFile"));
        for(XMLSize_t i = 0; i < nodeList->getLength(); ++i)
        {
            DOMElement *item = static_cast<DOMElement*>(nodeList->item(i));
            if(!item)
                continue;

            if(XMLString::compareString(item->getAttribute(X("ContentType")), X("HASHCODE")) == 0)
                continue;

            if(const XMLCh *b64 = item->getTextContent())
            {
                XMLSize_t size = 0;
                XMLByte *data = Base64::decodeToXMLByte(b64, &size);
                d->dataFiles.push_back(new DataFilePrivate(new stringstream(string((const char*)data, size)),
                    X(item->getAttribute(X("Filename"))), X(item->getAttribute(X("MimeType"))), X(item->getAttribute(X("Id")))));
                delete data;
            }

            Digest calc(URI_SHA1);
            SecureDOMParser::calcDigestOnNode(&calc, "http://www.w3.org/TR/2001/REC-xml-c14n-20010315", dom.get(), item);
            vector<unsigned char> digest = calc.result();
            XMLSize_t size = 0;
            if(XMLByte *out = Base64::encode(digest.data(), XMLSize_t(digest.size()), &size))
            {
                item->setAttribute(X("ContentType"), X("HASHCODE"));
                item->setAttribute(X("DigestType"), X("sha1"));
                item->setAttribute(X("DigestValue"), X((const char*)out));
                item->setTextContent(nullptr);
                delete out;
            }
        }

        DOMImplementationLS *pImplement = (DOMImplementationLS*)DOMImplementationRegistry::getDOMImplementation(X("LS"));
        unique_ptr<DOMLSOutput> pDomLsOutput(pImplement->createLSOutput());
        unique_ptr<DOMLSSerializer> pSerializer(pImplement->createLSSerializer());
        MemBufFormatTarget out;
        pDomLsOutput->setByteStream(&out);
        pSerializer->setNewLine(X("\n"));
        pSerializer->write(dom.get(), pDomLsOutput.get());
        return new stringstream(string((const char*)out.getRawBuffer(), out.getLen()));
    }
    catch(const XMLException& e)
    {
        THROW("Failed to parse DDoc XML: %s", X(e.getMessage()).toString().c_str());
    }
    catch(const DOMException& e)
    {
        THROW("Failed to parse DDoc XML: %s", X(e.getMessage()).toString().c_str());
    }
    catch(...)
    {
        THROW("Failed to parse DDoc XML.");
    }
}

Signature* SiVaContainer::prepareSignature(Signer *)
{
    THROW("Not implemented.");
}

vector<Signature *> SiVaContainer::signatures() const
{
    return d->signatures;
}

void SiVaContainer::removeDataFile(unsigned int)
{
    THROW("Not supported.");
}

void SiVaContainer::removeSignature(unsigned int)
{
    THROW("Not implemented.");
}

void SiVaContainer::save(const string &)
{
    THROW("Not implemented.");
}

Signature *SiVaContainer::sign(Signer *)
{
    THROW("Not implemented.");
}
