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

#include "ASiContainer.h"
#include "Conf.h"
#include "DataFile_p.h"
#include "XMLDocument.h"
#include "crypto/Connect.h"
#include "util/File.h"

#include "json.hpp"

#include <fstream>
#include <sstream>

using namespace digidoc;
using namespace digidoc::util;
using namespace std;
using json = nlohmann::json;

template <class T>
constexpr T base64_enc_size(T n) noexcept
{
    return ((n + 2) / 3) << 2;
}

static auto base64_decode(string_view data) {
    static constexpr array<uint8_t, 128> T{
        0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
        0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
        0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x3E, 0x64, 0x64, 0x64, 0x3F,
        0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
        0x64, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x64, 0x64, 0x64, 0x64, 0x64,
        0x64, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x64, 0x64, 0x64, 0x64, 0x64
    };

    string buf;
    buf.reserve(base64_enc_size(data.size()));
    auto out = make_unique<stringstream>(std::move(buf));
    int value = 0;
    int bits = -8;
    for(auto c: data)
    {
        if(c == '\r' || c == '\n' || c == ' ' || static_cast<uint8_t>(c) > 128)
            continue;
        uint8_t check = T[c];
        if(check == 0x64)
            break;
        value = (value << 6) + check;
        if(bits += 6; bits < 0)
            continue;
        out->put(char((value >> bits) & 0xFF));
        bits -= 8;
    }
    return out;
}



class SiVaContainer::Private
{
public:
    std::filesystem::path path;
    string  mediaType;
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
    try {
        for(const Exception &exception: _exceptions)
            e.addCause(exception);
        if(!Exception::hasWarningIgnore(Exception::SignatureDigestWeak) &&
            Digest::isWeakDigest(_signatureMethod))
        {
            Exception ex(EXCEPTION_PARAMS("Signature digest weak"));
            ex.setCode(Exception::SignatureDigestWeak);
            e.addCause(ex);
        }
        if(_indication == "TOTAL-PASSED")
        {
            if(QES.contains(_signatureLevel) || _signatureLevel.empty() || policy == POLv1)
            {
                if(!e.causes().empty())
                    throw e;
                return;
            }
            Exception ex(EXCEPTION_PARAMS("Signing certificate does not meet Qualification requirements"));
            ex.setCode(Exception::CertificateIssuerMissing);
            e.addCause(ex);
        }
    } catch(const Exception &ex) {
        e.addCause(ex);
    } catch(...) {
        EXCEPTION_ADD(e, "Failed to validate signature");
    }
    if(!e.causes().empty())
        throw e;
}


SiVaContainer::SiVaContainer(const string &path, ContainerOpenCB *cb, bool useHashCode)
    : d(make_unique<Private>())
{
    DEBUG("SiVaContainer::SiVaContainer(%s, %d)", path.c_str(), useHashCode);
    unique_ptr<istream> ifs = make_unique<ifstream>(d->path = File::encodeName(path), ifstream::binary);
    auto fileName = File::fileName(path);
    istream *is = ifs.get();
    if(File::fileExtension(path, {"ddoc"}))
    {
        d->mediaType = "application/x-ddoc";
        ifs = parseDDoc(ifs, useHashCode);
        is = ifs.get();
    }
    else if(File::fileExtension(path, {"pdf"}))
    {
        d->mediaType = "application/pdf";
        d->dataFiles.push_back(new DataFilePrivate(std::move(ifs), fileName, "application/pdf"));
    }
    else if(File::fileExtension(path, {"asice", "sce", "asics", "scs"}))
    {
        ZipSerialize z(path, false);
        vector<string> list = z.list();
        if(list.front() != "mimetype")
            THROW("Missing mimetype");
        if(d->mediaType = ASiContainer::readMimetype(z);
            d->mediaType != ASiContainer::MIMETYPE_ASIC_E && d->mediaType != ASiContainer::MIMETYPE_ASIC_S)
            THROW("Unknown file");
        if(none_of(list.cbegin(), list.cend(), [](const string &file) {
                return file.starts_with("META-INF/") && util::File::fileExtension(file, {"p7s"});
            }))
            THROW("Unknown file");

        for(const string &file: list)
        {
            if(file == "mimetype" || file.starts_with("META-INF/"))
                continue;
            if(const auto directory = File::directory(file);
                directory.empty() || directory == "/" || directory == "./")
                d->dataFiles.push_back(new DataFilePrivate(z, file, "application/octet-stream"));
        }
    }
    else
        THROW("Unknown file");

    if(useHashCode && cb && !cb->validateOnline())
        THROW("Online validation disabled");

    array<unsigned char, 4800> buf{};
    string b64;
    is->clear();
    is->seekg(0);
    while(*is)
    {
        is->read((char*)buf.data(), buf.size());
        if(is->gcount() <= 0)
            break;

        size_t pos = b64.size();
        b64.resize(b64.size() + base64_enc_size(buf.size()));
        int size = EVP_EncodeBlock((unsigned char*)&b64[pos], buf.data(), int(is->gcount()));
        b64.resize(pos + size);
    }
    ifs.reset();

    string req = json({
        {"filename", fileName},
        {"document", std::move(b64)},
        {"signaturePolicy", "POLv4"}
    }).dump();
    Connect::Result r = Connect(CONF(verifyServiceUri), "POST", 0, CONF(verifyServiceCerts)).exec({
        {"Content-Type", "application/json;charset=UTF-8"}
    }, (const unsigned char*)req.c_str(), req.size());
    req.clear();

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
                s->_messageImprint = from_base64(info["timeAssertionMessageImprint"].get<string_view>());
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
            auto der = from_base64(certificate.value<string_view>("content", {}));
            if(certificate["type"] == "SIGNING")
                s->_signingCertificate = X509Cert(der, X509Cert::Der);
            if(certificate["type"] == "REVOCATION")
                s->_ocspCertificate = X509Cert(der, X509Cert::Der);
            if(certificate["type"] == "SIGNATURE_TIMESTAMP")
                s->_tsCertificate = X509Cert(der, X509Cert::Der);
            if(certificate["type"] == "ARCHIVE_TIMESTAMP")
                s->_tsaCertificate = X509Cert(der, X509Cert::Der);
        }
        for(const json &error: signature.value<json>("errors", {}))
        {
            string message = error["content"];
            if(message.find("Bad digest for DataFile", 0) != string::npos && useHashCode)
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
            else if(message.find("Bad digest for DataFile") != string::npos)
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

unique_ptr<Container> SiVaContainer::openInternal(const string &path, ContainerOpenCB *cb)
{
    try {
        return unique_ptr<Container>(new SiVaContainer(path, cb, true));
    } catch(const Exception &e) {
        if(e.msg().find("Bad digest for DataFile") != string::npos)
            return unique_ptr<Container>(new SiVaContainer(path, cb, false));
        if(e.msg() == "Unknown file")
            return {};
        throw;
    }
}

unique_ptr<istream> SiVaContainer::parseDDoc(const unique_ptr<istream> &ddoc, bool useHashCode)
{
    try
    {
        auto doc = XMLDocument::openStream(*ddoc, {}, true);
        for(auto dataFile = doc/"DataFile"; dataFile; dataFile++)
        {
            auto contentType = dataFile["ContentType"];
            if(contentType == "HASHCODE")
                THROW("Currently supports only content types EMBEDDED_BASE64 for DDOC format");
            if(contentType != "EMBEDDED_BASE64")
                continue;
            d->dataFiles.push_back(new DataFilePrivate(base64_decode(dataFile),
                string(dataFile["Filename"]),
                string(dataFile["MimeType"]),
                string(dataFile["Id"])));
            if(!useHashCode)
                continue;
            Digest calc(URI_SHA1);
            doc.c14n(calc, XMLDocument::C14D_ID_1_0, dataFile);
            dataFile.setProperty("ContentType", "HASHCODE");
            dataFile.setProperty("DigestType", "sha1");
            dataFile.setProperty("DigestValue", to_base64(calc.result()));
            dataFile = std::string_view{};
        }
        auto result = make_unique<stringstream>();
        if(!doc.save([&result](const char *data, size_t size) { result->write(data, streamsize(size)); }))
            THROW("Failed to save DDoc");
        return result;
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
    if(d->path.empty() || path.empty())
        return; // This is readonly container
    auto dest = File::encodeName(path);
    if(std::error_code ec;
        !std::filesystem::copy_file(d->path, dest, ec))
        THROW("Failed to save container");
    d->path = std::move(dest);
}

Signature *SiVaContainer::sign(Signer * /*signer*/)
{
    THROW("Not implemented.");
}
