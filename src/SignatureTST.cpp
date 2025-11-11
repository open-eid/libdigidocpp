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
#include <map>
#include <sstream>

using namespace digidoc;
using namespace std;

constexpr const char* TST_MIMETYPE {"application/vnd.etsi.timestamp-token"};

struct SignatureTST::Data {
    string name, mime, data;
    unique_ptr<map<string, vector<unsigned char>>> cache = make_unique<map<string, vector<unsigned char>>>();

    Data(string _name, string _mime, string _data)
        : name(std::move(_name))
        , mime(std::move(_mime))
        , data(std::move(_data))
    {}

    Digest digest(Digest digest = {}) const
    {
        digest.update((const unsigned char*)data.data(), data.size());
        return digest;
    }
    const vector<unsigned char>& digestCache(string method) const
    {
        if (auto it = cache->find(method); it != cache->cend()) {
            return it->second;
        }
        return (*cache)[std::move(method)] = digest(Digest(method)).result();
    }
};

SignatureTST::SignatureTST(bool manifest, const ZipSerialize &z, ASiC_S *asicSDoc)
    : asicSDoc(asicSDoc)
{
    string data = z.read("META-INF/timestamp.tst");
    timestampToken = make_unique<TS>((const unsigned char*)data.data(), data.size());
    if(manifest)
    {
        XMLSchema schema(util::File::path(Conf::instance()->xsdPath(), "en_31916201v010101.xsd"));
        string file = "META-INF/ASiCArchiveManifest.xml";
        string mime = "text/xml";
        while(!file.empty()) {
            stringstream xml(z.read(file).operator string());
            XMLDocument doc = XMLDocument::openStream(xml, {"ASiCManifest", ASiContainer::ASIC_NS});
            schema.validate(doc);
            auto ref = doc/"SigReference";
            string uri = util::File::fromUriPath(ref["URI"]);
            metadata.emplace_back(std::move(file), std::move(mime), xml.str());
            metadata.emplace_back(std::move(uri), string(ref["MimeType"]), z.read(uri));
            file.clear();

            for(auto ref = doc/"DataObjectReference"; ref; ref++)
            {
                if(ref["Rootfile"] == "true")
                {
                    file = util::File::fromUriPath(ref["URI"]);
                    mime = ref["MimeType"];
                }
            }
        }
    }
    metadata.emplace_back("META-INF/timestamp.tst", TST_MIMETYPE, std::move(data));
}

SignatureTST::SignatureTST(ASiC_S *asicSDoc, Signer *signer)
    : asicSDoc(asicSDoc)
{
    auto *dataFile = static_cast<DataFilePrivate*>(asicSDoc->dataFiles().front());
    Digest digest;
    dataFile->digest(digest);
    timestampToken = make_unique<TS>(digest, signer->userAgent());
    vector<unsigned char> der = *timestampToken;
    metadata.emplace_back("META-INF/timestamp.tst", TST_MIMETYPE, string{der.cbegin(), der.cend()});
}

SignatureTST::~SignatureTST() = default;

X509Cert SignatureTST::ArchiveTimeStampCertificate() const
{
    if(auto list = ArchiveTimeStamps(); !list.empty())
        return list.front().cert;
    return X509Cert();
}

string SignatureTST::ArchiveTimeStampTime() const
{
    if(auto list = ArchiveTimeStamps(); !list.empty())
        return list.front().time;
    return {};
}

vector<TSAInfo> SignatureTST::ArchiveTimeStamps() const
{
    vector<TSAInfo> result;
    for(auto i = next(metadata.crbegin()), end = metadata.crend(); i != end; ++i)
    {
        if(i->mime != TST_MIMETYPE)
            continue;
        TS ts((const unsigned char*)i->data.data(), i->data.size());
        result.push_back({ts.cert(), util::date::to_string(ts.time())});
    }
    return result;
}

void SignatureTST::extendSignatureProfile(Signer *signer)
{
    auto nextName = [this](const char *pattern) {
        string name = Log::format(pattern, 1);
        for(size_t i = 1;
             any_of(metadata, [&name](const auto &f) { return f.name == name; });
             name = Log::format(pattern, ++i));
        return name;
    };
    string tstName = nextName("META-INF/timestamp%03zu.tst");
    auto doc = XMLDocument::create("ASiCManifest", ASiContainer::ASIC_NS, "asic");
    auto ref = doc + "SigReference";
    ref.setProperty("MimeType", TST_MIMETYPE);
    ref.setProperty("URI", tstName);

    auto addRef = [&doc](const string &name, string_view mime, bool root, const Digest &digest) {
        auto ref = doc + "DataObjectReference";
        ref.setProperty("MimeType", mime);
        ref.setProperty("URI", util::File::toUriPath(name));
        if(root)
            ref.setProperty("Rootfile", "true");
        auto method = ref + DigestMethod;
        method.setNS(method.addNS(DSIG_NS, "ds"));
        method.setProperty("Algorithm", digest.uri());
        auto value = ref + DigestValue;
        value.setNS(value.addNS(DSIG_NS, "ds"));
        value = digest.result();
    };

    DataFile *file = asicSDoc->dataFiles().front();
    Digest digest;
    static_cast<DataFilePrivate*>(file)->digest(digest);
    addRef(file->fileName(), file->mediaType(), false, digest);
    for(auto &data: metadata)
    {
        bool root = data.name == "META-INF/ASiCArchiveManifest.xml";
        if(root)
            data.name = nextName("META-INF/ASiCArchiveManifest%03zu.xml");
        addRef(data.name, data.mime, root, data.digest());
    }

    string data;
    doc.save([&data](const char *buf, size_t size) {
        data.append(buf, size);
        return size;
    }, true);
    auto i = metadata.insert(metadata.cbegin(), {"META-INF/ASiCArchiveManifest.xml", "text/xml", std::move(data)});
    vector<unsigned char> der = TS(i->digest(), signer->userAgent());
    metadata.insert(next(i), {tstName, TST_MIMETYPE, string{der.cbegin(), der.cend()}});
}

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
    const DataFile *file = asicSDoc->dataFiles().front();
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
        vector<string> list {file->fileName()};
        for(auto i = metadata.crbegin(); i != metadata.crend(); ++i)
        {
            if(i->mime != "text/xml")
                continue;
            istringstream is(i->data);
            XMLDocument doc = XMLDocument::openStream(is, {"ASiCManifest", ASiContainer::ASIC_NS});
            vector<string> add;
            add.reserve(metadata.size());
            for(auto ref = doc/"DataObjectReference"; ref; ref++)
            {
                string method((ref/DigestMethod)["Algorithm"]);
                const auto &uri = add.emplace_back(util::File::fromUriPath(ref["URI"]));
                vector<unsigned char> digest;
                if(file->fileName() == uri)
                    digest = file->calcDigest(method);
                else
                {
                    auto j = find_if(metadata.cbegin(), metadata.cend(), [&uri](const auto &d) { return d.name == uri; });
                    if(j == metadata.cend())
                        THROW("File not found '%s'.", uri.c_str());
                    digest = j->digestCache(std::move(method));
                }
                if(vector<unsigned char> digestValue = ref/DigestValue; digest != digestValue)
                    THROW("Reference '%s' digest does not match", uri.c_str());
            }
            if(auto sigRef = doc/"SigReference"; sigRef["MimeType"] == TST_MIMETYPE)
            {
                const auto &uri = add.emplace_back(util::File::fromUriPath(sigRef["URI"]));
                auto j = find_if(metadata.cbegin(), metadata.cend(), [uri](const auto &d) { return d.name == uri; });
                if(j == metadata.cend())
                    THROW("SigReference %s is missing", uri.c_str());
                TS ts((const unsigned char*)j->data.data(), j->data.size());
                ts.verify(i->digestCache(ts.digestMethod()));
            }
            else
                THROW("SigReference is missing");
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

vector<unsigned char> SignatureTST::dataToSign() const
{
    return asicSDoc->dataFiles().front()->calcDigest(signatureMethod());
}

vector<unsigned char> SignatureTST::messageImprint() const
{
    return timestampToken->messageImprint();
}

void SignatureTST::setSignatureValue(const vector<unsigned char> & /*signatureValue*/)
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
    for(auto i = metadata.crbegin(); i != metadata.crend(); ++i)
        z.addFile(i->name, asicSDoc->zproperty(i->name))(i->data);
}
