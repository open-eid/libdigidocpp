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

#include "ASiC_S.h"

#include "Conf.h"
#include "SignatureTST.h"
#include "SignatureXAdES_LTA.h"
#include "crypto/Signer.h"
#include "util/algorithm.h"
#include "util/File.h"
#include "util/log.h"

#include <sstream>

using namespace digidoc;
using namespace digidoc::util;
using namespace std;

struct ASiC_S::Data {
    std::string name, mime, data;

    Digest digest(Digest digest = {}) const
    {
        digest.update((const unsigned char*)data.data(), data.size());
        return digest;
    }
};



/**
 * Initialize ASiCS container.
 */
ASiC_S::ASiC_S()
    : ASiContainer(MIMETYPE_ASIC_S)
{}

/**
 * Opens ASiC-S container from a file
 */
ASiC_S::ASiC_S(const string &path)
    : ASiContainer(MIMETYPE_ASIC_S)
{
    auto z = load(path, false, {mediaType()});
    for(const string &file: z.list())
    {
        if(file == "mimetype")
            continue;
        if(file == "META-INF/timestamp.tst")
        {
            if(!signatures().empty())
                THROW("Can not add signature to ASiC-S container which already contains a signature.");
            string tst = z.extract<stringstream>(file).str();
            addSignature(make_unique<SignatureTST>(tst, this));
            metadata.push_back({file, "application/vnd.etsi.timestamp-token", std::move(tst)});
        }
        else if(file == "META-INF/signatures.xml")
        {
            if(!signatures().empty())
                THROW("Can not add signature to ASiC-S container which already contains a signature.");
            auto data = z.extract<stringstream>(file);
            auto signatures = make_shared<Signatures>(data, mediaType());
            for(auto s = signatures->signature(); s; s++)
                addSignature(make_unique<SignatureXAdES_LTA>(signatures, s, this));
        }
        else if(file == "META-INF/ASiCArchiveManifest.xml")
        {
            function<void(const string &, string_view)> add = [this, &add, &z](const string &file, string_view mime) {
                auto xml = z.extract<stringstream>(file);
                XMLDocument doc = XMLDocument::openStream(xml, {"ASiCManifest", ASIC_NS});
                doc.validateSchema(util::File::path(Conf::instance()->xsdPath(), "en_31916201v010101.xsd"));

                for(auto ref = doc/"DataObjectReference"; ref; ref++)
                {
                    if(ref["Rootfile"] == "true")
                        add(util::File::fromUriPath(ref["URI"]), ref["MimeType"]);
                }

                auto ref = doc/"SigReference";
                string uri = util::File::fromUriPath(ref["URI"]);
                string tst = z.extract<stringstream>(uri).str();
                addSignature(make_unique<SignatureTST>(file, ::move(doc), tst, this));
                metadata.push_back({file, string(mime), xml.str()});
                metadata.push_back({uri, string(ref["MimeType"]), std::move(tst)});
            };
            add(file, "text/xml");
        }
        else if(starts_with(file, "META-INF/"))
            continue;
        else if(const auto directory = File::directory(file);
            !directory.empty() && directory != "/" && directory != "./")
            THROW("Subfolders are not supported %s", directory.c_str());
        else if(!dataFiles().empty())
            THROW("Can not add document to ASiC-S container which already contains a document.");
        else
            addDataFile(dataStream(file, z), file, "application/octet-stream");
    }

    if(dataFiles().empty())
        THROW("ASiC-S container does not contain any data objects.");
    if(signatures().empty())
        THROW("ASiC-S container does not contain any signatures.");
}

void ASiC_S::addDataFileChecks(const string &fileName, const string &mediaType)
{
    ASiContainer::addDataFileChecks(fileName, mediaType);
    if(!dataFiles().empty())
        THROW("Can not add document to ASiC-S container which already contains a document.");
}

unique_ptr<Container> ASiC_S::createInternal(const string &path)
{
    if(!util::File::fileExtension(path, {"asics", "scs"}))
        return {};
    DEBUG("ASiC_S::createInternal(%s)", path.c_str());
    auto doc = unique_ptr<ASiC_S>(new ASiC_S());
    doc->zpath(path);
    return doc;
}

void ASiC_S::addAdESSignature(istream & /*signature*/)
{
    THROW("Not implemented.");
}

void ASiC_S::canSave()
{
    if(auto list = signatures(); !list.empty() && list.front()->profile() != ASIC_TST_PROFILE)
        THROW("ASiC-S container supports only saving TimeStampToken signatures.");
}

Digest ASiC_S::fileDigest(const string &file, string_view method) const
{
    if(auto i = find_if(metadata.cbegin(), metadata.cend(), [&file](const auto &d) { return d.name == file; });
        i != metadata.cend())
        return i->digest(method);
    THROW("File not found %s.", file.c_str());
}

unique_ptr<Container> ASiC_S::openInternal(const string &path, ContainerOpenCB * /*cb*/)
{
    if (!isContainerSimpleFormat(path))
        return {};
    DEBUG("ASiC_S::openInternal(%s)", path.c_str());
    return unique_ptr<Container>(new ASiC_S(path));
}

Signature* ASiC_S::prepareSignature(Signer * /*signer*/)
{
    THROW("Not implemented.");
}

void ASiC_S::save(const ZipSerialize &s)
{
    if(zproperty("META-INF/manifest.xml").size && !createManifest().save(s.addFile("META-INF/manifest.xml", zproperty("META-INF/manifest.xml")), true))
        THROW("Failed to create manifest XML");
    for(const auto &[name, mime, data]: metadata)
        s.addFile(name, zproperty(name))(data);
}

Signature *ASiC_S::sign(Signer *signer)
{
    if(signer->profile() != ASIC_TST_PROFILE)
        THROW("ASiC-S container supports only TimeStampToken signing.");
    if(!signatures().empty())
        THROW("ASiC-S container supports only one TimeStampToken signature.");
    return addSignature(make_unique<SignatureTST>(this, signer));
}

/**
 * Detect ASiC format based on file extentions, mimetype or zip contents.<br/>
 * Container format is simple (ASiC-S) or extended (ASiC-E).
 *
 * @param path Path of the container.
 * @throws Exception
 */
bool ASiC_S::isContainerSimpleFormat(const string &path)
{
    DEBUG("isContainerSimpleFormat(path = '%s')", path.c_str());
    if(util::File::fileExtension(path, {"asice", "sce", "bdoc"}))
        return false;
    if(util::File::fileExtension(path, {"asics", "scs"}))
        return true;
    DEBUG("Check if ASiC/zip containter");
    try
    {
        ZipSerialize z(path, false);
        vector<string> list = z.list();
        return list.front() == "mimetype" && readMimetype(z) == MIMETYPE_ASIC_S;
    }
    catch(const Exception &)
    {
        // Ignore the exception: not ASiC/zip document
    }
    return false;
}
