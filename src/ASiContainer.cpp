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
#include "log.h"
#include "Signature.h"
#include "util/File.h"
#include "util/ZipSerialize.h"

#include <algorithm>
#include <ctime>
#include <fstream>
#include <sstream>
#include <map>

using namespace digidoc;
using namespace digidoc::util;
using namespace std;

namespace digidoc
{
class ASiContainer::Private
{
public:
    ZipSerialize::Properties readProperties(const string &file)
    {
        map<string, ZipSerialize::Properties>::const_iterator i = properties.find(file);
        if(i != properties.end())
            return i->second;

        time_t t = time(0);
        tm *filetime = gmtime(&t);
        ZipSerialize::Properties prop = { appInfo(), *filetime, 0 };
        return properties[file] = prop;
    }
    
    string path;
    vector<DataFile*> documents;
    vector<Signature*> signatures;
    map<string, ZipSerialize::Properties> properties;
};

}

const string ASiContainer::ASICE_EXTENSION = "asice";
const string ASiContainer::ASICE_EXTENSION_ABBR = "sce";
const string ASiContainer::ASICS_EXTENSION = "asics";
const string ASiContainer::ASICS_EXTENSION_ABBR = "scs";
const string ASiContainer::BDOC_EXTENSION = "bdoc";

const string ASiContainer::MIMETYPE_ASIC_E = "application/vnd.etsi.asic-e+zip";
const string ASiContainer::MIMETYPE_ASIC_S = "application/vnd.etsi.asic-s+zip";

/**
 * Initialize BDOC container.
 */
ASiContainer::ASiContainer()
 : d(new Private)
{
}

/**
 * Loads ASi container from a file.
 *
 * @param path name of the container file.
 * @param mimetypeRequired flag indicating if the mimetype must be present and checked.
 * @return returns zip serializer for the container.
 */
unique_ptr<ZipSerialize> ASiContainer::load(const string &path, bool mimetypeRequired)
{
    DEBUG("ASiContainer::ASiContainer(path = '%s')", path.c_str());
    unique_ptr<ZipSerialize> z( new ZipSerialize(d->path = path, false) );

    vector<string> list = z->list();
    if(list.empty())
        THROW("Failed to parse container");

    for(const string &file: list)
        d->properties[file] = z->properties(file);

    if(mimetypeRequired || find(list.begin(), list.end(), "mimetype") != list.end())
    {
        stringstream data;
        // ETSI TS 102 918: mimetype has to be the first in the archive;
        z->extract(list.front(), data);
        auto mimetype = readMimetype(data);
        DEBUG("mimetype = '%s'", mimetype.c_str());
        if(mimetype != mediaType())
        {
            THROW("Incorrect mimetype '%s'", mimetype.c_str());
        }
    }
    
    return z;
}

/**
 * Releases resources.
 */
ASiContainer::~ASiContainer()
{
    for_each(d->signatures.begin(), d->signatures.end(), [](Signature *s){ delete s; });
    for_each(d->documents.begin(), d->documents.end(), [](DataFile *file){ delete file; });
    delete d;
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
 * <p>
 * Read a datafile from container.
 * </p>
 * If expected size of the data is too big, then stream is written to temp file.
 *
 * @param path name of the file in zip container stream is used to read from.
 * @param z Zip container.
 * @return returns data as a stream.
 */
iostream* ASiContainer::dataStream(const string &path, const ZipSerialize &z) const
{
    iostream *data = nullptr;
    if(d->properties[path].size > MAX_MEM_FILE)
        data = new fstream(File::encodeName(File::tempFileName()).c_str(), fstream::in|fstream::out|fstream::binary|fstream::trunc);
    else
        data = new stringstream;
    
    z.extract(path, *data);
    return data;
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
    if(!d->signatures.empty())
        THROW("Can not add document to container which has signatures, remove all signatures before adding new document.");
    
    if(!File::fileExists(path))
        THROW("Document file '%s' does not exist.", path.c_str());
    
    for(const DataFile *file: d->documents)
    {
        if(path.compare(file->fileName()) == 0)
            THROW("Document with same file name '%s' already exists '%s'.", path.c_str(), file->fileName().c_str());
    }
    
    tm *filetime = File::modifiedTime(path);
    ZipSerialize::Properties prop = { appInfo(), *filetime, File::fileSize(path) };
    zproperty(File::fileName(path), prop);
    istream *is;
    if(prop.size > MAX_MEM_FILE)
    {
        is = new ifstream(File::encodeName(path).c_str(), ifstream::binary);
    }
    else
    {
        ifstream file(File::encodeName(path).c_str(), ifstream::binary);
        stringstream *data = new stringstream;
        if(file)
            *data << file.rdbuf();
        file.close();
        is = data;
    }
    
    addDataFile(is, File::fileName(path), mediaType);
}

void ASiContainer::addDataFile(istream *is, const string &fileName, const string &mediaType)
{
    if(!d->signatures.empty())
        THROW("Can not add document to container which has signatures, remove all signatures before adding new document.");
    
    for(DataFile *file: d->documents)
    {
        if(fileName == file->fileName())
            THROW("Document with same file name '%s' already exists '%s'.", fileName.c_str(), file->fileName().c_str());
    }
    
    d->documents.push_back(new DataFilePrivate(is, fileName, mediaType));
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
    
    if(d->documents.size() > id)
    {
        vector<DataFile*>::iterator it = (d->documents.begin() + id);
        delete *it;
        d->documents.erase(it);
    }
    else
    {
        THROW("Incorrect document id %u, there are only %u documents in container.", id, dataFiles().size());
    }
}

void ASiContainer::addSignature(Signature *signature)
{
    d->signatures.push_back(signature);
}


/**
 * Removes signature from container by signature id.
 *
 * @param id signature's id, which will be removed.
 * @throws ContainerException throws exception if the signature id is incorrect.
 */
void ASiContainer::removeSignature(unsigned int id)
{
    if(d->signatures.size() > id)
    {
        vector<Signature*>::iterator it = (d->signatures.begin() + id);
        delete *it;
        d->signatures.erase(it);
    }
    else
    {
        THROW("Incorrect signature id %u, there are only %u signatures in container.", id, d->signatures.size());
    }
}

void ASiContainer::deleteSignature(Signature* s)
{
    vector<Signature*>::iterator i = find(d->signatures.begin(), d->signatures.end(), s);
    if(i != d->signatures.end())
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
    return d->readProperties(file);
}

void ASiContainer::zproperty(const string &file, const ZipSerialize::Properties &prop)
{
    d->properties[file] = prop;
}


/**
 * Reads and parses container mimetype. Checks that the mimetype is supported.
 *
 * @param path path to container directory.
 * @throws IOException exception is thrown if there was error reading mimetype file from disk.
 * @throws ContainerException exception is thrown if the parsed mimetype is incorrect.
 */
string ASiContainer::readMimetype(istream &is)
{
    DEBUG("ASiContainer::readMimetype()");
    unsigned char bom[] = { 0, 0, 0 };
    is.read((char*)bom, sizeof(bom));
    // Contains UTF-16 BOM
    if((bom[0] == 0xFF && bom[1] == 0xEF) ||
       (bom[0] == 0xEF && bom[1] == 0xFF))
        THROW("Mimetype file must be UTF-8 format.");
    // does not contain UTF-8 BOM reset pos
    if(!(bom[0] == 0xEF && bom[1] == 0xBB && bom[2] == 0xBF))
        is.seekg(0, ios::beg);
    
    string text;
    is >> text;
    if(is.fail())
        THROW("Failed to read mimetype.");
    
    return text;
}
