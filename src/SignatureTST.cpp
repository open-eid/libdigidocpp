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

#include "SignatureTST.h"

#include "ASiC_S.h"
#include "Conf.h"
#include "DataFile_p.h"
#include "XMLDocument.h"
#include "crypto/Digest.h"
#include "crypto/Signer.h"
#include "crypto/TS.h"
#include "crypto/X509Cert.h"
#include "util/algorithm.h"
#include "util/DateTime.h"
#include "util/File.h"
#include "util/log.h"

#include <functional>
#include <sstream>

using namespace digidoc;
using namespace std;

struct SignatureTST::Data {
    std::string name, mime, data;
    bool root = false;

    Digest digest(Digest digest = {}) const
    {
        digest.update((const unsigned char*)data.data(), data.size());
        return digest;
    }
};

SignatureTST::SignatureTST(bool manifest, const ZipSerialize &z, ASiC_S *asicSDoc)
    : asicSDoc(asicSDoc)
{
    auto data = z.extract<stringstream>("META-INF/timestamp.tst").str();
    timestampToken = make_unique<TS>((const unsigned char*)data.data(), data.size());
    metadata.push_back({"META-INF/timestamp.tst", "application/vnd.etsi.timestamp-token", std::move(data)});
    if(!manifest)
        return;
    XMLSchema schema(util::File::path(Conf::instance()->xsdPath(), "en_31916201v010101.xsd"));
    function<void(const string &, string_view)> add = [this, &schema, &add, &z](const string &file, string_view mime) {
        auto xml = z.extract<stringstream>(file);
        XMLDocument doc = XMLDocument::openStream(xml, {"ASiCManifest", ASiContainer::ASIC_NS});
        schema.validate(doc);

        for(auto ref = doc/"DataObjectReference"; ref; ref++)
        {
            if(ref["Rootfile"] == "true")
                add(util::File::fromUriPath(ref["URI"]), ref["MimeType"]);
        }

        auto ref = doc/"SigReference";
        string uri = util::File::fromUriPath(ref["URI"]);
        string tst = z.extract<stringstream>(uri).str();
        metadata.push_back({file, string(mime), xml.str()});
        metadata.push_back({uri, string(ref["MimeType"]), std::move(tst)});
    };
    add("META-INF/ASiCArchiveManifest.xml", "text/xml");
}

SignatureTST::SignatureTST(ASiC_S *asicSDoc, Signer *signer)
    : asicSDoc(asicSDoc)
{
    auto *dataFile = static_cast<DataFilePrivate*>(asicSDoc->dataFiles().front());
    Digest digest;
    dataFile->digest(digest);
    timestampToken = make_unique<TS>(digest, signer->userAgent());
    vector<unsigned char> der = *timestampToken;
    metadata.push_back({"META-INF/timestamp.tst", "application/vnd.etsi.timestamp-token", {der.cbegin(), der.cend()}});
}

SignatureTST::~SignatureTST() = default;

X509Cert SignatureTST::TimeStampCertificate() const
{
    return timestampToken->cert();
}

string SignatureTST::TimeStampTime() const
{
    return util::date::to_string(timestampToken->time());
}

string SignatureTST::trustedSigningTime() const
{
    return TimeStampTime();
}

// DSig properties
string SignatureTST::id() const
{
    return timestampToken->serial();
}

string SignatureTST::claimedSigningTime() const
{
    return TimeStampTime();
}

X509Cert SignatureTST::signingCertificate() const
{
    return TimeStampCertificate();
}

string SignatureTST::signatureMethod() const
{
    return timestampToken->digestMethod();
}

void SignatureTST::validate() const
{
    Exception exception(EXCEPTION_PARAMS("Timestamp validation."));

    if(!timestampToken)
    {
        EXCEPTION_ADD(exception, "Failed to parse timestamp token.");
        throw exception;
    }
    DataFile *file = asicSDoc->dataFiles().front();
    vector<string> list {file->fileName()};
    try
    {
        auto digestMethod = signatureMethod();
        timestampToken->verify(file->calcDigest(digestMethod));
        if(!Exception::hasWarningIgnore(Exception::ReferenceDigestWeak) &&
            Digest::isWeakDigest(digestMethod))
        {
            Exception e(EXCEPTION_PARAMS("TimeStamp '%s' digest weak", digestMethod.c_str()));
            e.setCode(Exception::ReferenceDigestWeak);
            exception.addCause(e);
        }
    }
    catch(const Exception& e)
    {
        exception.addCause(e);
    }
    try
    {
        for(const auto &manifest: metadata)
        {
            if(manifest.mime != "text/xml")
                continue;
            istringstream is(manifest.data);
            XMLDocument doc = XMLDocument::openStream(is, {"ASiCManifest", ASiContainer::ASIC_NS});
            vector<string> add;
            for(auto ref = doc/"DataObjectReference"; ref; ref++)
            {
                string_view method = (ref/DigestMethod)["Algorithm"];
                const auto &uri = add.emplace_back(util::File::fromUriPath(ref["URI"]));
                vector<unsigned char> digest;
                if(file->fileName() == uri)
                    digest = file->calcDigest(string(method));
                else
                {
                    auto i = find_if(metadata.cbegin(), metadata.cend(), [&uri](const auto &d) { return d.name == uri; });
                    if(i == metadata.cend())
                        THROW("File not found '%s'.", uri.c_str());
                    digest = i->digest(method).result();
                }
                if(vector<unsigned char> digestValue = ref/DigestValue; digest != digestValue)
                    THROW("Reference '%s' digest does not match", uri.c_str());
            }
            // Check if all files in previous scope are present
            for(const string &uri: list)
            {
                if(!contains(add, uri))
                    THROW("Reference '%s' not found in manifest", uri.c_str());
            }
            list = std::move(add);
        }
    }
    catch (const Exception& e)
    {
        exception.addCause(e);
    }

    if(!exception.causes().empty())
        throw exception;
}

std::vector<unsigned char> SignatureTST::dataToSign() const
{
    return asicSDoc->dataFiles().front()->calcDigest(signatureMethod());
}

vector<unsigned char> SignatureTST::messageImprint() const
{
    return timestampToken->messageImprint();
}

void SignatureTST::setSignatureValue(const std::vector<unsigned char> & /*signatureValue*/)
{
    THROW("Not implemented.");
}

// Xades properties
string SignatureTST::profile() const
{
    return string(ASiC_S::ASIC_TST_PROFILE);
}

void SignatureTST::save(const ZipSerialize &z) const
{
    for(const auto &[name, mime, data, root]: metadata)
        z.addFile(name, asicSDoc->zproperty(name))(data);
}
