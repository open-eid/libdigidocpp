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

#include "RDoc.h"

#include "Conf.h"
#include "DataFile.h"
#include "log.h"
#include "crypto/Connect.h"
#include "crypto/X509Cert.h"
#include "util/File.h"

#include <xercesc/framework/MemBufInputSource.hpp>
#include <xercesc/sax2/Attributes.hpp>
#include <xercesc/sax2/SAX2XMLReader.hpp>
#include <xercesc/sax2/XMLReaderFactory.hpp>
#include <xercesc/sax2/DefaultHandler.hpp>
#include <xercesc/util/Base64.hpp>
#include <xercesc/util/XMLString.hpp>

#include <algorithm>
#if defined(__APPLE__) || defined(_WIN32)
#include <codecvt>
#endif
#include <fstream>
#include <locale>
#include <sstream>

using namespace digidoc;
using namespace digidoc::util;
using namespace std;
using namespace xercesc;

#ifdef _WIN32
#define _W(STR) (const XMLCh*)L##STR
#else
#define _W(STR) (const XMLCh*)u"" STR
#endif

namespace digidoc {

class RDocPrivate: public DefaultHandler
{
public:
    inline bool compare(const XMLCh *src, const XMLCh *dst)
    {
        return XMLString::compareString(src, dst) == 0;
    }

    inline static string toString(const XMLCh *chars)
    {
#if defined(__APPLE__) || defined(_WIN32)
        static wstring_convert<codecvt_utf8_utf16<char16_t>, char16_t> utf8;
        return utf8.to_bytes((char16_t*)chars);
#else // Older gcc-s do not support codecvt
        char *outbuf = XMLString::transcode(chars);
        string out(outbuf);
        XMLString::release(&outbuf);
        return out;
#endif
    }

    inline void trim(string &str)
    {
        str.erase(str.find_last_not_of(" \n\r\t") + 1);
    }

    inline X509Cert cert(const string &id)
    {
        string data = certs[id];
        if(data.empty())
            return X509Cert();
        XMLSize_t size = 0;
        XMLByte *out = Base64::decode((const XMLByte*)data.c_str(), &size);
        X509Cert cert(out, size);
        XMLPlatformUtils::fgMemoryManager->deallocate(out);
        return cert;
    }

    void startElement(const XMLCh* const /*uri*/,
                      const XMLCh* const localname,
                      const XMLCh* const /*qname*/,
                      const Attributes& attrs)
    {
        el = localname;
        switch(doc)
        {
        case Diagnostic:
            if(compare(el, _W("Signature")))
            {
                if(!s)
                    s = new SignatureRDOC;
                mode = Sign;
                s->_id = toString(attrs.getValue(_W("Id")));
            }
            else if(compare(el, _W("Timestamp")))
            {
                if(compare(attrs.getValue(_W("Type")), _W("SIGNATURE_TIMESTAMP")) && s->_tID.empty())
                    mode = TS;
                else if(compare(attrs.getValue(_W("Type")), _W("ARCHIVE_TIMESTAMP")) && s->_aID.empty())
                    mode = TSA;
                else
                    mode = Unknown;
            }
            else if(s && compare(el, _W("SigningCertificate")))
            {
                switch(mode)
                {
                case Sign: s->_sID = toString(attrs.getValue(_W("Id"))); break;
                case TS: s->_tID = toString(attrs.getValue(_W("Id"))); break;
                case TSA: s->_aID = toString(attrs.getValue(_W("Id"))); break;
                default: break;
                }
            }
            else if(compare(el, _W("Certificate")))
                curCertID = toString(attrs.getValue(_W("Id")));
            break;
        case Report:
            if(compare(el, _W("Signature")))
            {
                string id = toString(attrs.getValue(_W("Id")));
                for(Signature *_s: signatures)
                {
                    if(_s->id() == id)
                        s = static_cast<SignatureRDOC*>(_s);
                }
            }
            break;
        default: break;
        }
    }

    void endElement(const XMLCh* const /*uri*/,
                    const XMLCh* const localname,
                    const XMLCh* const /*qname*/)
    {
        switch(doc)
        {
        case Response:
            if(compare(localname, _W("faultstring")))
                mode = Error;
            break;
        case Diagnostic:
            if(compare(localname, _W("Signature")))
            {
                if(s)
                    signatures.push_back(s);
                s = nullptr;
                mode = Unknown;
            }
            break;
        case Report:
            if(compare(localname, _W("Signature")))
            {
                trim(s->_result);
                s = nullptr;
            }
            break;
        default: break;
        }
    }

    void endDocument()
    {
        switch(doc)
        {
        case Response:
            if(compare(el, _W("faultstring")))
                mode = Unknown;
            break;
        case Diagnostic:
            for(Signature *_s: signatures)
            {
                SignatureRDOC *s = static_cast<SignatureRDOC*>(_s);
                s->_signCert = cert(s->_sID);
                s->_tsCert = cert(s->_tID);
                s->_aCert = cert(s->_aID);
                trim(s->_profile);
                trim(s->_signatureMethod);
                trim(s->_signingTime);
                trim(s->_tsTime);
                trim(s->_aTime);
            }
        default: break;
        }
    }

    void characters(const XMLCh* const chars, const XMLSize_t /*lenght*/)
    {
        switch(doc)
        {
        case Response:
            if(compare(el, _W("faultstring")))
                error += toString(chars);
            /*if(compare(el, _W("xmlDetailedReport")))
                DetailedReport += toString(chars);*/
            if(compare(el, _W("xmlDiagnosticData")))
                DiagnosticData += toString(chars);
            if(compare(el, _W("xmlSimpleReport")))
                SimpleReport += toString(chars);
            break;
        case Diagnostic:
            switch(mode)
            {
            case Sign:
                if(s && compare(el, _W("DateTime")))
                    s->_signingTime += toString(chars);
                if(s && compare(el, _W("SignatureFormat")))
                    s->_profile += toString(chars);
                if(s && compare(el, _W("EncryptionAlgoUsedToSignThisToken")))
                    s->_signatureMethod += toString(chars);
                if(s && compare(el, _W("KeyLengthUsedToSignThisToken")))
                    s->_signatureMethod += toString(chars);
                if(s && compare(el, _W("DigestAlgoUsedToSignThisToken")))
                    s->_signatureMethod += toString(chars);
                trim(s->_signatureMethod);
                break;
            case TS:
                if(s && compare(el, _W("ProductionTime")))
                    s->_tsTime += toString(chars);
                break;
            case TSA:
                if(s && compare(el, _W("ProductionTime")))
                    s->_aTime += toString(chars);
                break;
            default:
                if(compare(el, _W("X509Data")))
                    certs[curCertID] += toString(chars);
                break;
            }
            break;
        case Report:
            if(s && compare(el, _W("Indication")))
                s->_result += toString(chars);
            if(s && compare(el, _W("SubIndication")))
                s->_resultDetails += toString(chars);
            if(s && compare(el, _W("Error")))
                s->_resultDetails += toString(chars);
            break;
        default: break;
        }
    }

    void fatalError(const SAXParseException &e)
    {
        for(Signature *s: signatures)
            delete s;
        delete s;
        throw e;
    }

    // Documents
    enum Document
    {
        Response,
        Diagnostic,
        Report
    } doc = Response;
    string error;
    string DetailedReport, DiagnosticData, SimpleReport;

    // DiagnosticData
    const XMLCh *el = nullptr;
    string curCertID;
    enum Mode
    {
        Unknown,
        Error,
        Sign,
        TS,
        TSA
    } mode = Unknown;
    SignatureRDOC *s = nullptr;
    map<string, string> certs;

    // Result
    vector<DataFile*> dataFiles;
    vector<Signature*> signatures;
};
}



std::vector<unsigned char> DataFileRDOC::calcDigest(const string &) const
{
    THROW("Not implemented.");
}

void DataFileRDOC::saveAs(const string &path) const
{
    ofstream ofs(File::encodeName(path).c_str(), ofstream::binary);
    saveAs(ofs);
    ofs.close();
}

void DataFileRDOC::saveAs(ostream &os) const
{
    _is->clear();
    _is->seekg(0);
    os << _is->rdbuf();
}


vector<unsigned char> SignatureRDOC::dataToSign() const
{
    THROW("Not implemented.");
}

string SignatureRDOC::trustedSigningTime() const
{
    return _tsTime.empty() ? _signingTime : _tsTime;
}

void SignatureRDOC::setSignatureValue(const vector<unsigned char> &)
{
    THROW("Not implemented.");
}

void SignatureRDOC::validate() const
{
    if(_result != "VALID")
        THROW_CAUSE(EXCEPTION(_resultDetails.c_str()), "Signature validation");
}



RDoc::RDoc(const string &path)
    : d(new RDocPrivate)
{
    string req =
        "<?xml version='1.0' encoding='UTF-8'?>"
        "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">"
        "<SOAP-ENV:Body>"
        "<m:validateDocument xmlns:m=\"http://ws.dss.esig.europa.eu/\">"
        "<document>"
        "<bytes>";
    DataFileRDOC *f = new DataFileRDOC;
    f->_id = f->_fileName = File::fileName(path);
    f->_mediaType = "application/pdf";
    f->_is.reset(new ifstream(File::encodeName(path).c_str(), ifstream::binary));
    f->_is->seekg(0, istream::end);
    istream::pos_type pos = f->_is->tellg();
    f->_fileSize = pos < 0 ? 0 : (unsigned long)pos;
    f->_is->seekg(0, istream::beg);

    d->dataFiles.push_back(f);
    XMLByte buf[48*100];
    while( *(f->_is) )
    {
        f->_is->read((char*)buf, 48*100);
        if(f->_is->gcount() <= 0)
            break;

        XMLSize_t size = 0;
        XMLByte *out = Base64::encode(buf, XMLSize_t(f->_is->gcount()), &size);
        if(out)
            req.append((char*)out, size);
        XMLPlatformUtils::fgMemoryManager->deallocate(out);
    }
    req += "</bytes>"
        "<mimeType>PDF</mimeType>"
        "</document>"
        "<diagnosticDataToBeReturned>true</diagnosticDataToBeReturned>"
        "</m:validateDocument>"
        "</SOAP-ENV:Body>"
        "</SOAP-ENV:Envelope>";

    Connect::Result r = Connect(CONF(verifyServiceUri), "POST", 0).exec({
        {"Content-Type", "text/xml;charset=UTF-8"},
        {"SOAPAction", "\"\""}
    }, vector<unsigned char>(req.c_str(), req.c_str()+req.size()));

    unique_ptr<SAX2XMLReader> parser(XMLReaderFactory::createXMLReader());
    parser->setFeature(XMLUni::fgSAX2CoreValidation, true);
    parser->setFeature(XMLUni::fgSAX2CoreNameSpaces, true);   // optional

    parser->setContentHandler(d);
    parser->setErrorHandler(d);

    try {
        d->doc = RDocPrivate::Response;
        parser->parse(MemBufInputSource(
            (const XMLByte*)r.content.c_str(), r.content.size(), "Response.xml"));

        d->doc = RDocPrivate::Diagnostic;
        parser->parse(MemBufInputSource(
            (const XMLByte*)d->DiagnosticData.c_str(), d->DiagnosticData.size(), "DiagnosticData.xml"));

        d->doc = RDocPrivate::Report;
        parser->parse(MemBufInputSource(
            (const XMLByte*)d->SimpleReport.c_str(), d->SimpleReport.size(), "SimpleReport.xml"));
    }
    catch (const XMLException &e)
    {
        THROW("Failed to parse document: %s %u",
              RDocPrivate::toString(e.getMessage()).c_str(), e.getSrcLine());
    }
    catch (const SAXParseException &e)
    {
        THROW_CAUSE(EXCEPTION(d->error.c_str()), "Failed to parse document: %s %u:%u",
              RDocPrivate::toString(e.getMessage()).c_str(), e.getLineNumber(), e.getColumnNumber());
    }
    catch (...)
    {
        THROW("Failed to parse document");
    }
}

RDoc::~RDoc()
{
    for(const Signature *s: d->signatures)
        delete s;
    for(const DataFile *f: d->dataFiles)
        delete f;
    delete d;
}

void RDoc::addDataFile(const string &, const string &)
{
    THROW("Not supported.");
}

void RDoc::addDataFile(istream *, const string &, const string &)
{
    THROW("Not supported.");
}

void RDoc::addAdESSignature(istream &)
{
    THROW("Not supported.");
}

Container* RDoc::createInternal(const string &)
{
    return nullptr;
}

string RDoc::mediaType() const
{
    return "application/pdf";
}

vector<DataFile *> RDoc::dataFiles() const
{
    return d->dataFiles;
}

Container* RDoc::openInternal(const string &path)
{
    size_t pos = path.find_last_of(".");
    if(pos == string::npos)
        return nullptr;
    string ext = path.substr(pos + 1);
    transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    if(ext != "pdf")
        return nullptr;
    return new RDoc(path);
}

Signature* RDoc::prepareSignature(Signer *)
{
    THROW("Not implemented.");
}

vector<Signature *> RDoc::signatures() const
{
    return d->signatures;
}

void RDoc::removeDataFile(unsigned int)
{
    THROW("Not supported.");
}

void RDoc::removeSignature(unsigned int)
{
    THROW("Not implemented.");
}

void RDoc::save(const string &)
{
    THROW("Not implemented.");
}

Signature *RDoc::sign(Signer *)
{
    THROW("Not implemented.");
}
