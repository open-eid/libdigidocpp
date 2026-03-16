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

#include "ASiContainer.h"

#include "DataFile_p.h"
#include "Signature.h"
#include "XMLDocument.h"
#include "util/algorithm.h"
#include "util/File.h"
#include "util/log.h"

#include <array>
#include <ctime>
#include <fstream>
#include <map>
#include <sstream>

using namespace digidoc;
using namespace digidoc::util;
using namespace std;

struct ASiContainer::Private
{
    string path, mimetype;
    vector<DataFile*> documents;
    vector<Signature*> signatures;
    map<string, ZipSerialize::Properties, std::less<>> properties;
};

/**
 * Initialize Container.
 */
ASiContainer::ASiContainer(const string &path, string_view mimetype)
    : d(make_unique<Private>(path, string(mimetype)))
{}

XMLDocument ASiContainer::createManifest() const
{
    DEBUG("ASiContainer::createManifest()");
    auto doc = XMLDocument::create("manifest", MANIFEST_NS, "manifest");
    doc.setProperty("version", "1.2", MANIFEST_NS);
    auto add = [&doc](string_view path, string_view mime) {
        auto file = doc+"file-entry";
        file.setProperty("full-path", path, MANIFEST_NS);
        file.setProperty("media-type", mime, MANIFEST_NS);
    };
    add("/", mediaType());
    for(const DataFile *file: dataFiles())
        add(file->fileName(), file->mediaType());
    return doc;
}

/**
 * Loads Container from a file.
 *
 * @param path name of the container file.
 * @param mimetypeRequired flag indicating if the mimetype must be present and checked.
 * @param supported supported mimetypes.
 * @return returns zip serializer for the container.
 */
ZipSerialize ASiContainer::load(bool mimetypeRequired, const set<string_view> &supported)
{
    DEBUG("ASiContainer::ASiContainer(path = '%s')", d->path.c_str());
    ZipSerialize z(d->path, false);
    vector<string> list = z.list();

    // ETSI TS 102 918: mimetype has to be the first in the archive
    if(mimetypeRequired && list.front() != "mimetype")
        THROW("required mimetype not found");

    if(list.front() == "mimetype")
    {
        d->mimetype = z.mimetype();
        if(!contains(supported, d->mimetype))
            THROW("Incorrect mimetype '%s'", d->mimetype.c_str());
    }
    DEBUG("mimetype = '%s'", d->mimetype.c_str());

    for(const string &file: list)
        d->properties[file] = z.properties(file);

    return z;
}

string ASiContainer::mediaType() const
{
    return d->mimetype;
}

/**
 * Releases resources.
 */
ASiContainer::~ASiContainer()
{
    for_each(d->signatures.cbegin(), d->signatures.cend(), default_delete<Signature>());
    for_each(d->documents.cbegin(), d->documents.cend(), default_delete<DataFile>());
}

/**
 * Returns document referenced by document id.
 *
 * @return returns dataFiles.
 */
vector<DataFile*> ASiContainer::dataFiles() const
{
    return d->documents;
}

/**
 * Returns signature referenced by signature id.
 *
 * @return returns signature referenced by signature id.
 * @throws ContainerException throws exception if the signature id is incorrect.
 */
vector<Signature *> ASiContainer::signatures() const
{
    return d->signatures;
}

/**
 * Adds document to the container. Documents can be removed from container only
 * after all signatures are removed.
 *
 * @param path path of a document, which is added to the container.
 * @param mediaType Mimetype of the file
 * @throws ContainerException exception is thrown if the document path is incorrect or document
 *         with same file name already exists. Also no document can be added if the
 *         container already has one or more signatures.
 */
void ASiContainer::addDataFile(const string &path, const string &mediaType)
{
    string fileName = File::fileName(path);
    addDataFileChecks(fileName, mediaType);
    auto nativePath = File::encodeName(path);
    auto size = File::fileSize(nativePath);
    if(size == 0)
        THROW("Document file '%s' does not exist or is empty.", path.c_str());

    unique_ptr<istream> is = make_unique<ifstream>(nativePath, ifstream::binary);
    if(!*is)
        THROW("Failed to open file for reading: %s.", path.c_str());
    if(size <= MAX_MEM_FILE)
    {
        auto data = make_unique<stringstream>();
        *data << is->rdbuf();
        is = std::move(data);
    }
    d->properties[fileName] = { appInfo(), File::modifiedTime(path), size };
    d->documents.push_back(new DataFilePrivate(std::move(is), std::move(fileName), mediaType));
}

void ASiContainer::addDataFile(unique_ptr<istream> is, const string &fileName, const string &mediaType)
{
    addDataFileChecks(fileName, mediaType);
    if(fileName.find_last_of("/\\") != string::npos)
        THROW("Document file '%s' cannot contain directory path.", fileName.c_str());
    d->documents.push_back(new DataFilePrivate(std::move(is), fileName, mediaType));
}

void ASiContainer::addDataFileChecks(const string &fileName, const string &mediaType)
{
    if(!d->signatures.empty())
        THROW("Can not add document to container which has signatures, remove all signatures before adding new document.");
    if(fileName == "mimetype")
        THROW("mimetype is reserved file.");
    if(any_of(d->documents.cbegin(), d->documents.cend(), [&](DataFile *file) { return fileName == file->fileName(); }))
        THROW("Document with same file name '%s' already exists.", fileName.c_str());
    if(mediaType.find('/') == string::npos)
        THROW("MediaType does not meet format requirements (RFC2045, section 5.1) '%s'.", mediaType.c_str());
}

void ASiContainer::addDataFilePrivate(DataFile *dataFile)
{
    d->documents.push_back(dataFile);
}

/**
 * Removes document from container by document id. Documents can be
 * removed from container only after all signatures are removed.
 *
 * @param id document's id, which will be removed.
 * @throws ContainerException throws exception if the document id is incorrect or there are
 *         one or more signatures.
 */
void ASiContainer::removeDataFile(unsigned int id)
{
    if(!d->signatures.empty())
        THROW("Can not remove document from container which has signatures, remove all signatures before removing document.");
    if(id >= d->documents.size())
        THROW("Incorrect document id %u, there are only %zu documents in container.", id, dataFiles().size());
    auto it = d->documents.cbegin() + id;
    delete *it;
    d->documents.erase(it);
}

Signature* ASiContainer::addSignature(unique_ptr<Signature> &&signature)
{
    d->signatures.push_back(signature.release());
    return d->signatures.back();
}

/**
 * Removes signature from container by signature id.
 *
 * @param id signature's id, which will be removed.
 * @throws ContainerException throws exception if the signature id is incorrect.
 */
void ASiContainer::removeSignature(unsigned int id)
{
    if(id >= d->signatures.size())
        THROW("Incorrect signature id %u, there are only %zu signatures in container.", id, d->signatures.size());
    auto it = d->signatures.cbegin() + id;
    delete *it;
    d->signatures.erase(it);
}

void ASiContainer::deleteSignature(Signature* s)
{
    if(auto i = find(d->signatures.cbegin(), d->signatures.cend(), s); i != d->signatures.cend())
        d->signatures.erase(i);
    delete s;
}

void ASiContainer::save(const string &path)
{
    if(dataFiles().empty())
        THROW("Can not save, container is empty.");
    canSave();
    if(!path.empty())
        d->path = path;
    ZipSerialize s(d->path, true);
    s.addFile("mimetype", zproperty("mimetype"), false)(mediaType());

    array<char,10240> buf{};
    for(const DataFile *file: dataFiles())
    {
        auto f = s.addFile(file->fileName(), zproperty(file->fileName()));
        const auto &is = static_cast<const DataFilePrivate*>(file)->m_is;
        is->clear();
        is->seekg(0);
        while(*is)
        {
            is->read(buf.data(), buf.size());
            if(auto size = is->gcount(); size > 0)
                f(buf.data(), size_t(size));
        }
    }

    save(s);
}

const string& ASiContainer::path() const
{
    return d->path;
}

const ZipSerialize::Properties& ASiContainer::zproperty(string_view file) const
{
    if(auto i = d->properties.find(file); i != d->properties.cend())
        return i->second;
    return d->properties[string(file)] = { appInfo(), time(nullptr), 0 };
}
