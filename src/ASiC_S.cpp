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

#include "Container.h"
#include "DataFile_p.h"
#include "SignatureTST.h"
#include "log.h"
#include "crypto/Digest.h"
#include "util/File.h"
#include "util/ASiContainer.h"
#include "util/ZipSerialize.h"

#include <algorithm>
#include <fstream>
#include <map>
#include <sstream>
#include <set>

#define MAX_MEM_FILE 500*1024*1024

using namespace digidoc;
using namespace digidoc::util;
using namespace std;

namespace digidoc
{
class ASiC_SPrivate
{
public:
    ZipSerialize::Properties propertie(const string &file)
    {
        map<string, ZipSerialize::Properties>::const_iterator i = properties.find(file);
        if(i != properties.end())
            return i->second;

        time_t t = time(0);
        tm *filetime = gmtime(&t);
        ZipSerialize::Properties prop = { appInfo(), *filetime, 0 };
        return properties[file] = prop;
    }

    static const string MANIFEST_NAMESPACE;

    string path;
    vector<DataFile*> documents;
    vector<Signature*> signatures;
    map<string, ZipSerialize::Properties> properties;
};
}

const string ASiC_SPrivate::MANIFEST_NAMESPACE = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";

/**
 * Initialize ASiCS container.
 */
ASiC_S::ASiC_S()
 : d(new ASiC_SPrivate)
{
}

/**
 * Opens ASiC-S container from a file
 */

ASiC_S::ASiC_S(const string &path)
 : d(new ASiC_SPrivate)
{
    DEBUG("ASiC_S::ASiC_S(path = '%s')", path.c_str());
    ZipSerialize z(d->path = path, false);

    vector<string> list = z.list();
    if(list.empty())
        THROW("Failed to parse container");

    for(const string &file: list)
        d->properties[file] = z.properties(file);

    loadContainer(z, list);
}

/**
 * Releases resources.
 */
ASiC_S::~ASiC_S()
{
    for_each(d->signatures.begin(), d->signatures.end(), [](Signature *s){ delete s; });
    for_each(d->documents.begin(), d->documents.end(), [](DataFile *file){ delete file; });
    delete d;
}

void ASiC_S::save(const string &path)
{
    THROW("Not implemented.");
}

void ASiC_S::addDataFile(const string &path, const string &mediaType)
{
    THROW("Not implemented.");
}

void ASiC_S::addDataFile(istream *is, const string &fileName, const string &mediaType)
{
    THROW("Not implemented.");
}

Container* ASiC_S::createInternal(const string &path)
{
    return nullptr;
}

/**
 * Returns document referenced by document id.
 *
 * @return returns dataFiles.
 */
vector<DataFile*> ASiC_S::dataFiles() const
{
    return d->documents;
}

void ASiC_S::removeDataFile(unsigned int id)
{
    THROW("Not implemented.");
}

/**
 * @return returns ASiC-S container mimetype.
 */
string ASiC_S::mediaType() const
{
    return digidoc::util::asic::ASICS_MIMETYPE;
}

void ASiC_S::addAdESSignature(istream &sigdata)
{
    THROW("Not implemented.");
}

Container* ASiC_S::openInternal(const string &path)
{
    return new ASiC_S(path);
}

/**
 * Returns signature referenced by signature id.
 *
 * @param id signature id.
 * @return returns signature referenced by signature id.
 * @throws ContainerException throws exception if the signature id is incorrect.
 */
vector<Signature *> ASiC_S::signatures() const
{
    return d->signatures;
}

void ASiC_S::removeSignature(unsigned int id)
{
    THROW("Not implemented.");
}

/**
 * Reads and parses container mimetype. Checks that the mimetype is supported.
 *
 * @param z zip file.
 * @throws IOException exception is thrown if there was error reading mimetype file from disk.
 * @throws Exception exception is thrown if the parsed mimetype is incorrect.
 */
void ASiC_S::readMimetype(const ZipSerialize &z)
{
    DEBUG("ASiC_S::readMimetype()");

    stringstream iss;
    z.extract("mimetype", iss);
    string mimetype = digidoc::util::asic::readMimetype(iss);
    if(mimetype != digidoc::util::asic::ASICS_MIMETYPE)
        THROW("Incorrect mimetype '%s'", mimetype.c_str());
}

void ASiC_S::validateDataObjects()
{
    const auto dataFiles = d->documents.size();
    if(dataFiles < 1)
    {
        THROW("ASiC-S container does not contain any data objects.");
    }
    if(dataFiles > 1)
    {
        THROW("ASiC-S container contains more than one data objects.");
    }
}

void ASiC_S::extractTimestamp(const ZipSerialize &z)
{
    stringstream data;
    z.extract("META-INF/timestamp.tst", data);
    d->signatures.push_back(new SignatureTST(data, this));
}

/**
 * Load container (datafile and timestamp).
 *
 * @param z Zip stream.
 * @param list List of files contained in the container.
 * @throws IOException exception is thrown if the manifest.xml file parsing failed.
 * @throws ContainerException
 */
void ASiC_S::loadContainer(const ZipSerialize &z, const vector<string> &list)
{
    DEBUG("ASiC_S::loadFileAndTimestamp()");
    const string metaInf = "META-INF/";

    for(const string &file: list)
    {
        if(file == "mimetype" ||
           file.substr(0, metaInf.size()) == metaInf)
            continue;

        const auto directory = File::directory(file);
        if(directory.empty() || directory == "/" || directory == "./")
        {
            iostream *data = nullptr;
            if(d->properties[file].size > MAX_MEM_FILE)
                data = new fstream(File::encodeName(File::tempFileName()).c_str(), fstream::in|fstream::out|fstream::binary|fstream::trunc);
            else
                data = new stringstream;
            z.extract(file, *data);
            d->documents.push_back(new DataFilePrivate(data, file, "application/octet-stream"));
        }
    }

    validateDataObjects();
    extractTimestamp(z);
}

Signature* ASiC_S::prepareSignature(Signer *signer)
{
    THROW("Not implemented.");
}

Signature *ASiC_S::sign(Signer* signer)
{
    THROW("Not implemented.");
}
