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

#include "PDF.h"

#include "Conf.h"
#include "DataFile_p.h"
#include "log.h"
#include "SignatureCAdES_T.h"
#include "crypto/Digest.h"
#include "crypto/OCSP.h"
#include "crypto/OpenSSLHelpers.h"
#include "crypto/Signer.h"
#include "crypto/X509CertStore.h"
#include "util/File.h"
#include "util/DateTime.h"

#include <podofo/podofo.h>

#include <openssl/ts.h>

#include <fstream>

using namespace digidoc;
using namespace digidoc::util;
using namespace PoDoFo;
using namespace std;

namespace digidoc {

class DSSPdfSigIncMemDocument: public PdfSigIncMemDocument
{
public:
    DSSPdfSigIncMemDocument(const char* pszInpFilename): PdfSigIncMemDocument(pszInpFilename) {}
    PdfAcroForm* GetAcroForm() { return GetExistedAcroForm(nullptr); }
};

class PDF::Private
{
public:
    string path;
    vector<DataFile*> dataFiles;
    vector<Signature*> signatures;
    vector<OCSP> ocsps;
};

class SignaturePDF: public SignatureCAdES_T
{
public:
    string _id, pdftime;
    vector<string> roles;
    vector<unsigned char> _data;
    vector<OCSP> *ocsps;

    SignaturePDF(Signer *signer, vector<unsigned char> data): SignatureCAdES_T(signer), _data(std::move(data)) {}
    SignaturePDF(const vector<unsigned char> &signature, vector<unsigned char> data): SignatureCAdES_T(signature), _data(std::move(data)) {}


    string id() const override { return _id; }
    string claimedSigningTime() const override
    {
        string time = SignatureCAdES_T::claimedSigningTime();
        return time.empty() ? pdftime : time;
    }

    void validate(const std::string &policy) const override
    {
        Exception exception(EXCEPTION_PARAMS("Signature validation"));
        try {
            SignatureCAdES_T::validate(policy);
        } catch(const Exception &e) {
            for(const Exception &ex: e.causes())
                exception.addCause(ex);
        }

        try {
            if(ocsps->empty())
                THROW("No OCSP responses found");

            /*
             * Find OCSP response that matches with signingCertificate.
             * If none is found throw all OCSP validation exceptions.
             */
            bool foundSignerOCSP = false;
            vector<Exception> ocspExceptions;
            for(const OCSP &ocsp: *ocsps)
            {
                try {
                    ocsp.verifyResponse(signingCertificate());
                    foundSignerOCSP = true;
                    break;
                } catch(const Exception &e) {
                    ocspExceptions.push_back(e);
                }
            }
            if(!foundSignerOCSP)
            {
                for(const Exception &e: ocspExceptions)
                    exception.addCause(e);
            }
        } catch(const Exception &e) {
            exception.addCause(e);
        }
        if(!exception.causes().empty())
            throw exception;
    }
    vector<unsigned char> dataToSign() const override { return _data; }
    void setSignatureValue(const vector<unsigned char> & /*signatureValue*/) override {}


    string profile() const override
    {
        if(TimeStampTime().empty()) return "PAdES_BASELINE_BES";
        return OCSPProducedAt().empty() ? "PAdES_BASELINE_T" : "PAdES_BASELINE_LT";
    }
    vector<string> signerRoles() const override { return roles; }

    std::string OCSPProducedAt() const override { return date::ASN1TimeToXSD(ocsp().producedAt()); }
    X509Cert OCSPCertificate() const override { return ocsp().responderCert(); }

    OCSP ocsp() const
    {
        for(const OCSP &ocsp: *ocsps)
        {
            try {
                ocsp.verifyResponse(signingCertificate());
                return ocsp;
            } catch(const Exception &) {
            }
        }
        return OCSP(nullptr, 0);
    }
};

}



PDF::PDF(const string &path)
    : d(new Private)
{
    d->path = path;
}

PDF::~PDF()
{
    for_each(d->signatures.begin(), d->signatures.end(), [](Signature *s){ delete s; });
    for_each(d->dataFiles.begin(), d->dataFiles.end(), [](DataFile *file){ delete file; });
    delete d;
}

void PDF::addDataFile(const string & /*path*/, const string & /*mediaType*/)
{
    THROW("Not supported.");
}

void PDF::addDataFile(istream * /*is*/, const string & /*fileName*/, const string & /*mediaType*/)
{
    THROW("Not supported.");
}

void PDF::addAdESSignature(istream & /*signature*/)
{
    THROW("Not supported.");
}

unique_ptr<Container> PDF::createInternal(const string & /*path*/)
{
    return nullptr;
}

vector<DataFile *> PDF::dataFiles() const
{
    return d->dataFiles;
}

string PDF::mediaType() const
{
    return "application/pdf";
}

unique_ptr<Container> PDF::openInternal(const string &path)
{
    if(File::fileExtension(path) != "pdf")
        return {};

    DEBUG("PDF:openInternal(%s)", path.c_str());
    unique_ptr<ifstream> is(new ifstream(File::encodeName(path).c_str(), ifstream::binary));
    string line;
    getline(*is, line);
    if(line.compare(0, 7, "%PDF-1.") != 0)
        return {};

    unique_ptr<PDF> doc(new PDF(path));
    try {
        PdfMemDocument parser(path.c_str());
        for(const PdfObject *obj: parser.GetObjects())
        {
            if(!obj->IsDictionary())
                continue;

            const PdfObject *type = obj->GetDictionary().GetKey("Type");
            if(type != nullptr && type->IsName() && type->GetName().GetName() == "Sig")
            {
                const PdfObject *filter =  obj->GetDictionary().GetKey("Filter");
                const PdfObject *subFilter =  obj->GetDictionary().GetKey("SubFilter");
                const PdfObject *byteRangeObj =  obj->GetDictionary().GetKey("ByteRange");
                const PdfObject *contents =  obj->GetDictionary().GetKey("Contents");
                const PdfObject *date =  obj->GetDictionary().GetKey("M");
                const PdfObject *name =  obj->GetDictionary().GetKey("Name");
                const PdfObject *reason =  obj->GetDictionary().GetKey("Reason");

                if(filter == nullptr || subFilter == nullptr || byteRangeObj == nullptr || contents == nullptr ||
                   filter->GetName().GetName() != "Adobe.PPKLite" ||
                   (subFilter->GetName().GetName() != "ETSI.CAdES.detached" && subFilter->GetName().GetName() != "adbe.pkcs7.detached"))
                    continue;

                PdfArray byteRange = byteRangeObj->GetArray();
                if(byteRange.GetSize() != 4)
                    continue;

                string signature(size_t((byteRange[2].GetNumber() - 1) - (byteRange[1].GetNumber() + 1)), 0);
                is->seekg(byteRange[1].GetNumber() + 1);
                is->read(&signature[0], streamsize(signature.size()));

                vector<unsigned char> signeddata(size_t(byteRange[1].GetNumber() + byteRange[3].GetNumber()));
                is->seekg(byteRange[0].GetNumber());
                is->read((char*)signeddata.data(), byteRange[1].GetNumber());
                is->seekg(byteRange[2].GetNumber());
                is->read((char*)&signeddata[size_t(byteRange[1].GetNumber())], byteRange[3].GetNumber());

                SignaturePDF *s = new SignaturePDF(File::hexToBin(signature), signeddata);
                if(name != nullptr && name->IsString())
                    s->_id = name->GetString().GetStringUtf8();
                if(date != nullptr && date->IsString())
                    s->pdftime = date->GetString().GetStringUtf8();
                if(reason != nullptr && reason->IsString())
                    s->roles.push_back(reason->GetString().GetStringUtf8());
                s->ocsps = &doc->d->ocsps;
                doc->d->signatures.push_back(s);
            }

            PdfObject *ocsps = obj->GetIndirectKey("OCSPs");
            if(ocsps != nullptr && ocsps->IsArray())
            {
                for(const PdfObject &ocsp: ocsps->GetArray())
                {
                    const PdfObject *direct = &ocsp;
                    if(ocsp.IsReference())
                        direct = parser.GetObjects().GetObject(ocsp.GetReference());
                    if(direct == nullptr || !direct->IsDictionary())
                        continue;
                    const PdfStream *stream = direct->GetStream();
                    char *data = nullptr;
                    pdf_long length = 0;
                    stream->GetFilteredCopy(&data, &length);
                    doc->d->ocsps.emplace_back(OCSP((const unsigned char*)data, size_t(length)));
                    podofo_free(data);
                }
            }
        }
    } catch(const PdfError &e) {
        THROW_CAUSE(EXCEPTION(e.what()), "Failed to parse PDF.");
    }

    doc->d->dataFiles.push_back(new DataFilePrivate(move(is), File::fileName(path), "application/pdf", File::fileName(path)));
    return doc;
}

Signature* PDF::prepareSignature(Signer * /*signer*/)
{
    THROW("Not implemented.");
}

vector<Signature *> PDF::signatures() const
{
    return d->signatures;
}

void PDF::removeDataFile(unsigned int /*index*/)
{
    THROW("Not supported.");
}

void PDF::removeSignature(unsigned int /*index*/)
{
    THROW("Not supported.");
}

void PDF::save(const string &path)
{
    if(!path.empty() && d->path != path)
        d->path = path;
    d->dataFiles[0]->saveAs(d->path);
}

Signature *PDF::sign(Signer *signer)
{
    try {
        X509Cert issuer = X509CertStore::instance()->findIssuer(signer->cert(), X509CertStore::OCSP);
        OCSP ocspreq(signer->cert(), issuer, vector<unsigned char>(), mediaType(), false);
        vector<unsigned char> ocsp = ocspreq.toDer();

        string roles;
        for(const string &role: signer->signerRoles())
            roles += roles.empty() ? role : " / " + role;
        DSSPdfSigIncMemDocument doc(d->path.c_str());
        doc.GetSignatureField()->SetSignatureDate(PdfDate());
        doc.GetSignatureField()->SetSignatureReason(roles);
        doc.Initialize();

        PdfMemDocument *newdoc = static_cast<PdfMemDocument*>(doc.GetAcroForm()->GetDocument());
        PdfObject *catalog = newdoc->GetCatalog();
        PdfObject *DSS = catalog->GetIndirectKey("DSS");
        if(!DSS)
        {
            DSS = catalog->GetOwner()->CreateObject("DSS");
            catalog->GetDictionary().AddKey("DSS", DSS->Reference());
        }

        PdfObject *OCSPs = DSS->GetDictionary().GetKey("OCSPs");
        if(!OCSPs)
        {
            DSS->GetDictionary().AddKey("OCSPs", PdfArray());
            OCSPs = DSS->GetDictionary().GetKey("OCSPs");
        }

        PdfObject *OCSP = newdoc->GetObjects().CreateObject();
        OCSPs->GetArray().push_back(OCSP->Reference());

        PdfMemoryInputStream stream((const char*)ocsp.data(), pdf_long(ocsp.size()));
        OCSP->GetStream()->SetRawData(&stream, -1);

        PdfRefCountedBuffer buf;
        PdfOutputDevice device(&buf);
        PdfSignOutputDevice out(&device);
        out.SetSignatureSize(10*1024);
        doc.Write(&out);
        if(!out.HasSignaturePosition())
            return nullptr;

        out.AdjustByteRange();
        out.Seek(0);
        char buff[65536];
        size_t len = 0;
        vector<unsigned char> data;
        while((len = out.ReadForSignature(buff, 65536)) > 0)
        {
            char *p = buff;
            data.insert(data.end(), p, p + len);
        }

        unique_ptr<SignaturePDF> s(new SignaturePDF(signer, data));
        s->sign();
        s->extendSignatureProfile("PAdES_BASELINE_T");
        vector<unsigned char> der = *s;
        out.SetSignature(PdfData((const char*)der.data(), der.size()));

        DataFilePrivate *dataFile = static_cast<DataFilePrivate*>(d->dataFiles[0]);
        dataFile->m_is = make_shared<stringstream>(string(buf.GetBuffer(), buf.GetSize()));
        d->ocsps.push_back(ocspreq);
        s->ocsps = &d->ocsps;
        d->signatures.push_back(s.release());
        return d->signatures.back();
    } catch(const Exception &e) {
        THROW_CAUSE(e, "Failed to sign PDF.");
    } catch(const PdfError &e) {
        THROW_CAUSE(EXCEPTION(e.what()), "Failed to sign PDF.");
    }
}
