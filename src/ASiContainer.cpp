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
#include "util/DateTime.h"
#include "util/File.h"
#include "util/log.h"
#include "util/ZipSerialize.h"

#include <algorithm>
#include <array>
#include <ctime>
#include <fstream>
#include <map>
#include <sstream>

using namespace digidoc;
using namespace digidoc::util;
using namespace std;

constexpr unsigned long MAX_MEM_FILE = 500UL*1024UL*1024UL;

class ASiContainer::Private
{
public:
    string mimetype, path;
    vector<DataFile*> documents;
    vector<Signature*> signatures;
    map<string, ZipSerialize::Properties> properties;
    unique_ptr<ZipSerialize> z;
};

const string_view ASiContainer::ASICE_EXTENSION = "asice";
const string_view ASiContainer::ASICE_EXTENSION_ABBR = "sce";
const string_view ASiContainer::ASICS_EXTENSION = "asics";
const string_view ASiContainer::ASICS_EXTENSION_ABBR = "scs";
const string_view ASiContainer::BDOC_EXTENSION = "bdoc";

const string ASiContainer::MIMETYPE_ASIC_E = "application/vnd.etsi.asic-e+zip";
const string ASiContainer::MIMETYPE_ASIC_S = "application/vnd.etsi.asic-s+zip";
//https://signa.mitsoft.lt/static/signa-web/webResources/docs/ADOC_specification_approved20090907_EN.pdf
const string ASiContainer::MIMETYPE_ADOC = "application/vnd.lt.archyvai.adoc-2008";

/**
 * Initialize BDOC container.
 */
ASiContainer::ASiContainer(const string &mimetype)
    : d(make_unique<Private>())
{
    d->mimetype = mimetype;
}

/**
 * Loads ASi Container from a file.
 *
 * @param path name of the container file.
 * @param mimetypeRequired flag indicating if the mimetype must be present and checked.
 * @param supported supported mimetypes.
 * @return returns zip serializer for the container.
 */
ZipSerialize* ASiContainer::load(const string &path, bool mimetypeRequired, const set<string> &supported)
{
    DEBUG("ASiContainer::ASiContainer(path = '%s')", path.c_str());
    d->z = make_unique<ZipSerialize>(d->path = path, false);

    vector<string> list = d->z->list();
    if(list.empty())
        THROW("Failed to parse container");

    if(mimetypeRequired && list.front() != "mimetype")
        THROW("required mimetype not found");

    // ETSI TS 102 918: mimetype has to be the first in the archive
    if(list.front() == "mimetype")
    {
        d->mimetype = readMimetype(*d->z);
        DEBUG("mimetype = '%s'", d->mimetype.c_str());
        if(supported.find(d->mimetype) == supported.cend())
            THROW("Incorrect mimetype '%s'", d->mimetype.c_str());
    }

    for(const string &file: list)
        d->properties[file] = d->z->properties(file);

    return d->z.get();
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

DataFilePrivate* ASiContainer::dataFile(const std::string &path, const std::string &mediaType) const
{
    return new DataFilePrivate(d->z->stream(path), path, mediaType, d->properties[path].size);
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
    if(!File::fileExists(path))
        THROW("Document file '%s' does not exist.", path.c_str());

    ZipSerialize::Properties prop { appInfo(), File::modifiedTime(path), File::fileSize(path) };
    bool useTempFile = prop.size > MAX_MEM_FILE;
    zproperty(File::fileName(path), std::move(prop));
    unique_ptr<istream> is;
    if(useTempFile)
    {
        is = make_unique<ifstream>(File::encodeName(path), ifstream::binary);
    }
    else
    {
        auto data = make_unique<stringstream>();
        if(ifstream file{File::encodeName(path), ifstream::binary})
            *data << file.rdbuf();
        is = std::move(data);
    }
    d->documents.push_back(new DataFilePrivate(std::move(is), fileName, mediaType, prop.size));
}

void ASiContainer::addDataFile(unique_ptr<istream> is, const string &fileName, const string &mediaType)
{
    addDataFileChecks(fileName, mediaType);
    if(fileName.find_last_of("/\\") != string::npos)
        THROW("Document file '%s' cannot contain directory path.", fileName.c_str());
    istream::pos_type pos = is->tellg();
    d->documents.push_back(new DataFilePrivate(std::move(is), fileName, mediaType, pos < 0 ? 0 : (unsigned long)pos));
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

void ASiContainer::addDataFilePrivate(const string &fileName, const string &mediaType)
{
    d->documents.push_back(dataFile(fileName, mediaType));
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

void ASiContainer::zpath(const string &file)
{
    d->path = file;
}

string ASiContainer::zpath() const
{
    return d->path;
}

ZipSerialize::Properties ASiContainer::zproperty(const string &file) const
{
    if(auto i = d->properties.find(file); i != d->properties.cend())
        return i->second;
    return d->properties[file] = { appInfo(), time(nullptr), 0 };
}

void ASiContainer::zproperty(const string &file, ZipSerialize::Properties &&prop)
{
    d->properties[file] = std::move(prop);
}

/**
 * Reads and parses container mimetype. Checks that the mimetype is supported.
 *
 * @param path path to container directory.
 * @throws IOException exception is thrown if there was error reading mimetype file from disk.
 * @throws ContainerException exception is thrown if the parsed mimetype is incorrect.
 */
string ASiContainer::readMimetype(const ZipSerialize &z)
{
    DEBUG("ASiContainer::readMimetype()");
    auto is = z.stream("mimetype");
    string text;
    *is >> text;
    if(!is)
        THROW("Failed to read mimetype.");
    // Contains UTF-16 BOM
    if(text.rfind("\xFF\xEF", 0) == 0 || text.rfind("\xEF\xFF", 0) == 0)
        THROW("Mimetype file must be UTF-8 format.");
    // contains UTF-8 BOM, remove
    if(text.rfind("\xEF\xBB\xBF", 0) == 0)
        text.erase(text.cbegin(), text.cbegin() + 3);
    return text;
}
