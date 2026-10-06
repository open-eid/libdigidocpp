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

#include "DataFile_p.h"
#include "Exception.h"
#include "SiVaContainer.h"
#include "SignatureTST.h"
#include "SignatureXAdES_LTA.h"
#include "crypto/Signer.h"
#include "util/algorithm.h"
#include "util/File.h"
#include "util/log.h"

using namespace digidoc;
using namespace digidoc::util;
using namespace std;

/**
 * Initialize ASiCS container.
 */
ASiC_S::ASiC_S(const string &path, bool create, ContainerOpenCB *cb)
    : ASiContainer(path, MIMETYPE_ASIC_S)
{
    if(create)
        return;
    auto z = load(false, {mediaType()});
    bool foundTimestamp = false;
    bool foundManifest = false;
    for(const string &file: z.list())
    {
        if(file == "mimetype")
            continue;
        if(file == "META-INF/timestamp.tst")
            foundTimestamp = true;
        if(file == "META-INF/ASiCArchiveManifest.xml")
        {
            if(!containerSignatures().empty())
                THROW("Can not add signature to ASiC-S container which already contains a signature.");
            addSignature(make_unique<SignatureTST>(true, z, this));
            foundManifest = true;
        }
        else if(file == "META-INF/signatures.xml")
        {
            if(!containerSignatures().empty())
                THROW("Can not add signature to ASiC-S container which already contains a signature.");
            auto signatures = make_shared<Signatures>(XMLDocument::open(z.read(file)), mediaType());
            for(auto s = signatures->signature(); s; s++)
                addSignature(make_unique<SignatureXAdES_LTA>(signatures, s, this));
        }
        else if(starts_with(file, "META-INF/"))
            continue;
        else if(const auto directory = File::directory(file);
            !directory.empty() && directory != "/" && directory != "./")
            THROW("Subfolders are not supported %s", directory.c_str());
        else if(!containerDataFiles().empty())
            THROW("Can not add document to ASiC-S container which already contains a document.");
        else
            addDataFilePrivate(z, file, "application/octet-stream");
    }
    if(foundTimestamp && !foundManifest)
    {
        if(!containerSignatures().empty())
            THROW("Can not add signature to ASiC-S container which already contains a signature.");
        addSignature(make_unique<SignatureTST>(false, z, this));
    }

    if(containerDataFiles().empty())
        THROW("ASiC-S container does not contain any data objects.");
    if(containerSignatures().empty())
        THROW("ASiC-S container does not contain any signatures.");

    const auto documents = containerDataFiles();
    const auto containerSigs = containerSignatures();
    if(!cb || documents.size() != 1 || containerSigs.size() != 1 ||
        containerSigs.front()->profile() != ASIC_TST_PROFILE ||
        !File::fileExtension(documents.front()->fileName(), {"ddoc"}))
        return;

    try
    {
        auto *ddoc = static_cast<DataFilePrivate*>(documents.front());
        enclosedDDoc = SiVaContainer::openDDoc(*ddoc->m_is, ddoc->fileName(), cb);
    }
    catch(...) {}
}

void ASiC_S::addDataFileChecks(string_view fileName, const string &mediaType)
{
    ASiContainer::addDataFileChecks(fileName, mediaType);
    if(!containerDataFiles().empty())
        THROW("Can not add document to ASiC-S container which already contains a document.");
}

vector<DataFile*> ASiC_S::containerDataFiles() const
{
    return ASiContainer::dataFiles();
}

vector<DataFile*> ASiC_S::dataFiles() const
{
    return enclosedDDoc ? enclosedDDoc->dataFiles() : containerDataFiles();
}

vector<Signature*> ASiC_S::containerSignatures() const
{
    return ASiContainer::signatures();
}

void ASiC_S::removeSignature(unsigned int id)
{
    if(enclosedDDoc)
        THROW("Can not remove signatures from an ASiC-S container with an enclosed DDoc.");
    ASiContainer::removeSignature(id);
}

vector<Signature*> ASiC_S::signatures() const
{
    auto result = containerSignatures();
    if(enclosedDDoc)
    {
        auto enclosed = enclosedDDoc->signatures();
        result.insert(result.end(), enclosed.begin(), enclosed.end());
    }
    return result;
}

unique_ptr<Container> ASiC_S::createInternal(const string &path)
{
    if(!util::File::fileExtension(path, {"asics", "scs"}))
        return {};
    DEBUG("ASiC_S::createInternal(%s)", path.c_str());
    return unique_ptr<Container>(new ASiC_S(path, true));
}

void ASiC_S::addAdESSignature(istream & /*signature*/)
{
    THROW("Not implemented.");
}

void ASiC_S::canSave()
{
    if(auto list = containerSignatures(); !list.empty() && list.front()->profile() != ASIC_TST_PROFILE)
        THROW("ASiC-S container supports only saving TimeStampToken signatures.");
}

unique_ptr<Container> ASiC_S::openInternal(const string &path, ContainerOpenCB *cb)
{
    DEBUG("ASiC_S::openInternal(%s)", path.c_str());
    try
    {
        if(util::File::fileExtension(path, {"asice", "sce", "bdoc"}))
            return {};
        return unique_ptr<Container>(new ASiC_S(path, false, cb));
    }
    catch(const Exception &)
    {
        // Ignore the exception: not ASiC/zip document
    }
    return {};
}

Signature* ASiC_S::prepareSignature(Signer * /*signer*/)
{
    THROW("Not implemented.");
}

void ASiC_S::save(const ZipSerialize &s)
{
    if(const auto &prop = zproperty("META-INF/manifest.xml");
        prop.size && !createManifest().save(s.addFile("META-INF/manifest.xml", prop), true))
        THROW("Failed to create manifest XML");
    for(Signature *sig: containerSignatures())
        static_cast<SignatureTST*>(sig)->save(s);
}

Signature *ASiC_S::sign(Signer *signer)
{
    if(signer->profile() != ASIC_TST_PROFILE)
        THROW("ASiC-S container supports only TimeStampToken signing.");
    if(!containerSignatures().empty())
        THROW("ASiC-S container supports only one TimeStampToken signature.");
    return addSignature(make_unique<SignatureTST>(this, signer));
}
