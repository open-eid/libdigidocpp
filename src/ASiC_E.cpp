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

#include "ASiC_E.h"

#include "Conf.h"
#include "DataFile_p.h"
#include "SignatureXAdES_LTA.h"
#include "XMLDocument.h"
#include "crypto/Signer.h"
#include "util/File.h"

#include <algorithm>
#include <set>

using namespace digidoc;
using namespace digidoc::util;
using namespace std;

#define STR_VIEW_FMT(str) int(str.size()), str.data()

class ASiC_E::Private
{
public:
    string unique_name() const
    {
        string file;
        for(unsigned int i = 0; signatures.count(file = Log::format("META-INF/signatures%u.xml", i++)); );
        return file;
    }
    vector<DataFile*> metadata;
    map<string,Signatures*> signatures;
};

/**
 * Initialize BDOC container.
 */
ASiC_E::ASiC_E(const string &path, bool create) try
    : ASiContainer(path, MIMETYPE_ASIC_E)
    , d(make_unique<Private>())
{
    if(create)
        return;
    auto z = load(true, {MIMETYPE_ASIC_E, MIMETYPE_ADOC});
    auto doc = XMLDocument::open(z.read("META-INF/manifest.xml"), {"manifest", MANIFEST_NS});
    doc.validateSchema(File::path(Conf::instance()->xsdPath(), "OpenDocument_manifest_v1_2.xsd"));

    set<string_view> manifestFiles;
    bool mimeFound = false;
    for(auto file = doc/"file-entry"; file; file++)
    {
        auto full_path = file[{"full-path", MANIFEST_NS}];
        auto media_type = file[{"media-type", MANIFEST_NS}];
        DEBUG("full_path = '%.*s', media_type = '%.*s'", STR_VIEW_FMT(full_path), STR_VIEW_FMT(media_type));

        // ODF does not specify that mimetype should be first in manifest
        if(full_path == "/")
        {
            if(mimeFound)
                THROW("Manifest multiple entries defined for file '/'.");
            if(mediaType() != media_type)
                THROW("Manifest has incorrect container media type defined '%.*s', expecting '%s'.", STR_VIEW_FMT(media_type), mediaType().c_str());
            mimeFound = true;
            continue;
        }
        if(full_path.back() == '/') // Skip Directory entries
            continue;

        if(const auto &[pos, inserted] = manifestFiles.insert(full_path); !inserted)
            THROW("Manifest multiple entries defined for file '%.*s'.", STR_VIEW_FMT(full_path));
        if(mediaType() == MIMETYPE_ADOC &&
            (full_path.starts_with("META-INF/") || full_path.starts_with("metadata/")))
            d->metadata.push_back(new DataFilePrivate(z, string(full_path), string(media_type)));
        else
            addDataFilePrivate(new DataFilePrivate(z, string(full_path), string(media_type)));
    }
    if(!mimeFound)
        THROW("Manifest is missing mediatype file entry.");

    for(const string &file: z.list())
    {
        /**
         * http://www.etsi.org/deliver/etsi_ts/102900_102999/102918/01.03.01_60/ts_102918v010301p.pdf
         * 6.2.2 Contents of Container
         * 3) The root element of each "*signatures*.xml" content shall be either:
         */
        if(file.starts_with("META-INF/") && file.contains("signatures"))
        {
            try
            {
                loadSignatures(XMLDocument::open(z.read(file)), file);
            }
            catch(const Exception &e)
            {
                THROW_CAUSE(e, "Failed to parse signature '%s'.", file.c_str());
            }
            continue;
        }

        if(file == "mimetype" || file.starts_with("META-INF"))
            continue;
        if(manifestFiles.erase(file) == 0)
            THROW("File '%s' found in container is not described in manifest.", file.c_str());
    }
    if(!manifestFiles.empty())
        THROW("Manifest describes files that are not found in container.");
}
catch(const Exception &e)
{
    THROW_CAUSE(e, "Failed to parse manifest");
}
catch(...)
{
    THROW("Failed to parse manifest XML: Unknown exception");
}

ASiC_E::~ASiC_E()
{
    for_each(d->metadata.cbegin(), d->metadata.cend(), default_delete<DataFile>());
}

vector<DataFile*> ASiC_E::metaFiles() const
{
    return d->metadata;
}

/**
 * Saves the container using the <code>serializer</code> implementation provided in
 * <code>readFrom()</code> method.
 *
 * @throws Exception is thrown if there was a failure saving BDOC container. For example added
 *         document does not exist.
 * @throws Exception is thrown if ASiC_E class is not correctly initialized.
 */
void ASiC_E::save(const ZipSerialize &s)
{
    if(!createManifest().save(s.addFile("META-INF/manifest.xml", zproperty("META-INF/manifest.xml")), true))
        THROW("Failed to create manifest XML");

    std::set<Signatures*> saved;
    for(Signature *iter: signatures())
    {
        auto *signatures = static_cast<SignatureXAdES_B*>(iter)->signatures.get();
        if(!saved.insert(signatures).second)
            continue;
        auto name = find_if(d->signatures.cbegin(), d->signatures.cend(), [signatures](const auto &k){
            return k.second == signatures;
        });
        if(name == d->signatures.cend())
            THROW("Unkown signature object");
        if(!signatures->save(s.addFile(name->first, zproperty(name->first))))
            THROW("Failed to create signature XML file.");
    }
}

unique_ptr<Container> ASiC_E::createInternal(const string &path)
{
    DEBUG("ASiC_E::createInternal(%s)", path.c_str());
    return unique_ptr<Container>(new ASiC_E(path, true));
}

/**
 * Adds signature to the container. Default profile is TM
 *
 * @param sigdata signature, which is added to the container.
 * @throws Exception throws exception if there are no documents in container.
 */
void ASiC_E::addAdESSignature(istream &data)
{
    if(dataFiles().empty())
        THROW("No documents in container, can not add signature.");
    if(mediaType() != MIMETYPE_ASIC_E)
        THROW("'%s' format is not supported", mediaType().c_str());
    try
    {
        loadSignatures(XMLDocument::openStream(data), d->unique_name());
    }
    catch(const Exception &e)
    {
        THROW_CAUSE(e, "Failed to add signature.");
    }
}

void ASiC_E::canSave()
{
    if(mediaType() != MIMETYPE_ASIC_E)
        THROW("'%s' format is not supported", mediaType().c_str());
}

unique_ptr<Container> ASiC_E::openInternal(const string &path)
{
    DEBUG("ASiC_E::openInternal(%s)", path.c_str());
    return unique_ptr<Container>(new ASiC_E(path, false));
}

void ASiC_E::loadSignatures(XMLDocument &&doc, const string &file)
{
    auto signatures = make_shared<Signatures>(std::move(doc), mediaType());
    d->signatures.emplace(file, signatures.get());
    for(auto s = signatures->signature(); s; s++)
        addSignature(make_unique<SignatureXAdES_LTA>(signatures, s, this));
}

Signature* ASiC_E::prepareSignature(Signer *signer)
{
    if(mediaType() != MIMETYPE_ASIC_E)
        THROW("'%s' format is not supported", mediaType().c_str());
    if(dataFiles().empty())
        THROW("No documents in container, can not sign container.");
    if(!signer)
        THROW("Null pointer in ASiC_E::sign");
    auto signatures = make_shared<Signatures>();
    d->signatures.emplace(d->unique_name(), signatures.get());
    return addSignature(make_unique<SignatureXAdES_LTA>(signatures, newSignatureId(), this, signer));
}

Signature *ASiC_E::sign(Signer* signer)
{
    auto *s = static_cast<SignatureXAdES_LTA*>(prepareSignature(signer));
    try
    {
        s->setSignatureValue(signer->sign(s->signatureMethod(), s->dataToSign()));
        s->extendSignatureProfile(signer);
    }
    catch(const Exception& e)
    {
        deleteSignature(s);
        THROW_CAUSE(e, "Failed to sign container.");
    }
    return s;
}
