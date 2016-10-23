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

#include "ASiCSDoc.h"

#include "Container.h"
#include "Conf.h"
#include "DataFile_p.h"
#include "SignatureTST.h"
#include "log.h"
#include "crypto/Digest.h"
#include "crypto/Signer.h"
#include "util/File.h"
#include "util/ASiContainer.h"
#include "util/ZipSerialize.h"
#include "xml/OpenDocument_manifest.hxx"

#include <algorithm>
#include <fstream>
#include <set>

#define MAX_MEM_FILE 500*1024*1024

using namespace digidoc;
using namespace digidoc::util;
using namespace std;
using namespace manifest;

namespace digidoc
{
class ASiCSDocPrivate
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

const string ASiCSDocPrivate::MANIFEST_NAMESPACE = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";

/**
 * Initialize ASiCS container.
 */
ASiCSDoc::ASiCSDoc()
 : d(new ASiCSDocPrivate)
{
}

/**
 * Opens ASiC-S container from a file
 */

ASiCSDoc::ASiCSDoc(const string &path)
 : d(new ASiCSDocPrivate)
{
    DEBUG("ASiCSDoc::ASiCSDoc(path = '%s')", path.c_str());
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
ASiCSDoc::~ASiCSDoc()
{
    for_each(d->signatures.begin(), d->signatures.end(), [](Signature *s){ delete s; });
    for_each(d->documents.begin(), d->documents.end(), [](DataFile *file){ delete file; });
    delete d;
}

void ASiCSDoc::save(const string &path)
{
    THROW("Not implemented.");
}

void ASiCSDoc::addDataFile(const string &path, const string &mediaType)
{
    THROW("Not implemented.");
}

void ASiCSDoc::addDataFile(istream *is, const string &fileName, const string &mediaType)
{
    THROW("Not implemented.");
}

Container* ASiCSDoc::createInternal(const string &path)
{
    return nullptr;
}

/**
 * Returns document referenced by document id.
 *
 * @return returns dataFiles.
 */
vector<DataFile*> ASiCSDoc::dataFiles() const
{
    return d->documents;
}

void ASiCSDoc::removeDataFile(unsigned int id)
{
    THROW("Not implemented.");
}

/**
 * @return returns ASiC-S container mimetype.
 */
string ASiCSDoc::mediaType() const
{
    return digidoc::util::asic::ASICS_MIMETYPE;
}

void ASiCSDoc::addAdESSignature(istream &sigdata)
{
    THROW("Not implemented.");
}

Container* ASiCSDoc::openInternal(const string &path)
{
    return new ASiCSDoc(path);
}

/**
 * Returns signature referenced by signature id.
 *
 * @param id signature id.
 * @return returns signature referenced by signature id.
 * @throws ContainerException throws exception if the signature id is incorrect.
 */
vector<Signature *> ASiCSDoc::signatures() const
{
    return d->signatures;
}

void ASiCSDoc::removeSignature(unsigned int id)
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
void ASiCSDoc::readMimetype(const ZipSerialize &z)
{
    DEBUG("ASiCSDoc::readMimetype()");

    stringstream iss;
    z.extract("mimetype", iss);
    string mimetype = digidoc::util::asic::readMimetype(iss);
    if(mimetype != digidoc::util::asic::ASICS_MIMETYPE)
        THROW("Incorrect mimetype '%s'", mimetype.c_str());
}

/**
 * Load container (datafile and timestamp).
 *
 * @param z Zip stream.
 * @param list List of files contained in the container.
 * @throws IOException exception is thrown if the manifest.xml file parsing failed.
 * @throws ContainerException
 */
void ASiCSDoc::loadContainer(const ZipSerialize &z, const vector<string> &list)
{
    DEBUG("ASiCSDoc::loadContainer()");

    size_t mcount = count(list.begin(), list.end(), "META-INF/manifest.xml");
    if(mcount > 1)
    {
        THROW("Found multiple manifest files");
    }
    if(mcount < 1)
    {
        loadWithoutManifest(z, list);
    }
    else
    {
        parseManifestAndLoadFiles(z, list);
    }
}

void ASiCSDoc::validateDataObjects()
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

void ASiCSDoc::extractTimestamp(const ZipSerialize &z)
{
    stringstream data;
    z.extract("META-INF/timestamp.tst", data);
    d->signatures.push_back(new SignatureTST(data, this));
}

/**
 * Load container without the OpenDocument manifest.
 *
 * @param z Zip stream.
 * @param list List of files contained in the container.
 * @throws IOException exception is thrown if the manifest.xml file parsing failed.
 * @throws ContainerException
 */
void ASiCSDoc::loadWithoutManifest(const ZipSerialize &z, const vector<string> &list)
{
    DEBUG("ASiCSDoc::loadFileAndTimestamp()");
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

/**
 * Parses manifest file and checks that files described in manifest exist, also
 * checks that no extra file do exist that are not described in manifest.xml.
 *
 * Note: If non-ascii characters are present in XML data, we depend on the LANG variable to be set properly
 * (see iconv --list for the list of supported encoding values for libiconv).
 *
 * @param z zip file.
 * @param list List of files contained in the container.
 * @throws IOException exception is thrown if the manifest.xml file parsing failed.
 * @throws ContainerException
 */
void ASiCSDoc::parseManifestAndLoadFiles(const ZipSerialize &z, const vector<string> &list)
{
    try
    {
        stringstream manifestdata;
        z.extract("META-INF/manifest.xml", manifestdata);
        xml_schema::Properties properties;
        properties.schema_location(ASiCSDocPrivate::MANIFEST_NAMESPACE,
            File::fullPathUrl(Conf::instance()->xsdPath() + "/OpenDocument_manifest.xsd"));
        unique_ptr<Manifest> manifest(manifest::manifest(manifestdata, xml_schema::Flags::dont_initialize|xml_schema::Flags::dont_validate, properties).release());

        Manifest::File_entrySequence::const_iterator iter = manifest->file_entry().begin();
        if(iter->full_path() == "/" && mediaType() != iter->media_type())
            THROW("Manifest has incorrect ASiC-S container media type defined '%s', expecting '%s'.", iter->media_type().c_str(), mediaType().c_str());

        set<string> manifestFiles;
        for(iter++; iter != manifest->file_entry().end(); ++iter)
        {
            DEBUG("full_path = '%s', media_type = '%s'", iter->full_path().c_str(), iter->media_type().c_str());

            if(manifestFiles.find(iter->full_path()) != manifestFiles.end())
                THROW("Manifest multiple entries defined for file '%s'.", iter->full_path().c_str());

            size_t fcount = count(list.begin(), list.end(), iter->full_path());
            if(fcount < 1)
                THROW("File described in manifest '%s' does not exist in ASiC-S container.", iter->full_path().c_str());
            if(fcount > 1)
                THROW("Found multiple references of file '%s' in zip container.", iter->full_path().c_str());

            manifestFiles.insert(iter->full_path());
            iostream *data = nullptr;
            if(d->properties[iter->full_path()].size > MAX_MEM_FILE)
                data = new fstream(File::encodeName(File::tempFileName()).c_str(), fstream::in|fstream::out|fstream::binary|fstream::trunc);
            else
                data = new stringstream;
            z.extract(iter->full_path(), *data);
            d->documents.push_back(new DataFilePrivate(data, iter->full_path(), iter->media_type()));
        }

        for(const string &file: list)
        {
            if(file == "mimetype" ||
               file == "META-INF/" ||
               file == "META-INF/manifest.xml" ||
               file == "META-INF/timestamp.tst")
                continue;

            if(manifestFiles.find(file) == manifestFiles.end())
                THROW("File '%s' found in ASiC-S container is not described in manifest.", file.c_str());
        }
    }
    catch(const xsd::cxx::xml::invalid_utf16_string &)
    {
        THROW("Failed to parse manifest XML: %s", Conf::instance()->xsdPath().c_str());
    }
    catch(const xsd::cxx::xml::properties<char>::argument &e)
    {
        THROW("Failed to parse manifest XML: %s %s", e, Conf::instance()->xsdPath().c_str());
    }
    catch(const xsd::cxx::tree::unexpected_element<char> &e)
    {
        THROW("Failed to parse manifest XML: %s %s %s", Conf::instance()->xsdPath().c_str(), e.expected_name().c_str(), e.encountered_name().c_str());
    }
    catch(const xml_schema::Exception& e)
    {
        THROW("Failed to parse manifest XML: %s (xsd path: %s)", e.what(), Conf::instance()->xsdPath().c_str());
    }

    validateDataObjects();
    extractTimestamp(z);
}

Signature* ASiCSDoc::prepareSignature(Signer *signer)
{
    THROW("Not implemented.");
}

Signature *ASiCSDoc::sign(Signer* signer)
{
    THROW("Not implemented.");
}
