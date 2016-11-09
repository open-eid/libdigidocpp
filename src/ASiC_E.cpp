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

#include "Container.h"
#include "Conf.h"
#include "DataFile_p.h"
#include "SignatureA.h"
#include "log.h"
#include "crypto/Digest.h"
#include "crypto/Signer.h"
#include "util/File.h"
#include "util/ZipSerialize.h"
#include "xml/OpenDocument_manifest.hxx"
#include "xercesc/util/OutOfMemoryException.hpp"

#include <fstream>
#include <set>

#define MAX_MEM_FILE 500*1024*1024

using namespace digidoc;
using namespace digidoc::util;
using namespace std;
using namespace manifest;

namespace digidoc
{
class ASiC_EPrivate
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

const string ASiC_E::ASIC_MIMETYPE = "application/vnd.etsi.asic-e+zip";
const string ASiC_EPrivate::MANIFEST_NAMESPACE = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";

const string ASiC_E::BES_PROFILE = "BES";
const string ASiC_E::EPES_PROFILE = "EPES";
const string ASiC_E::ASIC_TM_PROFILE = "time-mark";
const string ASiC_E::ASIC_TS_PROFILE = "time-stamp";
const string ASiC_E::ASIC_TSA_PROFILE = ASIC_TS_PROFILE + "-archive";
const string ASiC_E::ASIC_TMA_PROFILE = ASIC_TM_PROFILE + "-archive";

/**
 * Initialize BDOC container.
 */
ASiC_E::ASiC_E()
 : d(new ASiC_EPrivate)
{
}

/**
 * Opens BDOC container from a file
 */

ASiC_E::ASiC_E(const string &path)
 : d(new ASiC_EPrivate)
{
    DEBUG("ASiC_E::ASiC_E(path = '%s')", path.c_str());
    ZipSerialize z(d->path = path, false);

    vector<string> list = z.list();
    if(list.empty())
        THROW("Failed to parse container");

    for(const string &file: list)
        d->properties[file] = z.properties(file);

    stringstream mimetype;
    z.extract(list.front(), mimetype);
    readMimetype(mimetype);
    parseManifestAndLoadFiles(z, list);
}

/**
 * Releases resources.
 */
ASiC_E::~ASiC_E()
{
    for_each(d->signatures.begin(), d->signatures.end(), [](Signature *s){ delete s; });
    for_each(d->documents.begin(), d->documents.end(), [](DataFile *file){ delete file; });
    delete d;
}

/**
 * Saves the container using the <code>serializer</code> implementation provided in
 * <code>readFrom()</code> method.
 *
 * @throws IOException is thrown if there was a failure saving BDOC container. For example added
 *         document does not exist.
 * @throws ContainerException is thrown if ASiC_E class is not correctly initialized.
 */
void ASiC_E::save(const string &path)
{
    if(d->documents.empty())
        THROW("Can not save, BDoc container is empty.");

    if(!path.empty())
        d->path = path;
    ZipSerialize s(d->path, true);

    stringstream mimetype;
    mimetype << mediaType();
    s.addFile("mimetype", mimetype, d->propertie("mimetype"), ZipSerialize::DontCompress);

    stringstream manifest;
    createManifest(manifest);
    s.addFile("META-INF/manifest.xml", manifest, d->propertie("META-INF/manifest.xml"));

    for(const DataFile *file: d->documents)
        s.addFile(file->fileName(), *(static_cast<const DataFilePrivate*>(file)->m_is.get()), d->propertie(file->fileName()));

    unsigned int i = 0;
    for(Signature *iter: d->signatures)
    {
        string file = Log::format("META-INF/signatures%u.xml", i++);
        SignatureBES *signature = static_cast<SignatureBES*>(iter);

        stringstream ofs;
        signature->saveToXml(ofs);
        s.addFile(file, ofs, d->propertie(file));
    }

    s.save();
}

/**
 * Adds document to the container. Documents can be removed from container only
 * after all signatures are removed.
 *
 * @param document a document, which is added to the container.
 * @throws ContainerException exception is thrown if the document path is incorrect or document
 *         with same file name already exists. Also no document can be added if the
 *         container already has one or more signatures.
 */
void ASiC_E::addDataFile(const string &path, const string &mediaType)
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
    d->properties[File::fileName(path)] = prop;
    if(prop.size > MAX_MEM_FILE)
    {
        d->documents.push_back(new DataFilePrivate(new ifstream(File::encodeName(path).c_str(), ifstream::binary),
            File::fileName(path), mediaType));
    }
    else
    {
        ifstream file(File::encodeName(path).c_str(), ifstream::binary);
        stringstream *data = new stringstream;
        if(file)
            *data << file.rdbuf();
        file.close();
        d->documents.push_back(new DataFilePrivate(data, File::fileName(path), mediaType));
    }
}

void ASiC_E::addDataFile(istream *is, const string &fileName, const string &mediaType)
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

Container* ASiC_E::createInternal(const string &path)
{
    ASiC_E *doc = new ASiC_E();
    doc->d->path = path;
    return doc;
}

/**
 * Returns document referenced by document id.
 *
 * @return returns dataFiles.
 */
vector<DataFile*> ASiC_E::dataFiles() const
{
    return d->documents;
}

/**
 * Removes document from container by document id. Documents can be
 * removed from container only after all signatures are removed.
 *
 * @param id document's id, which will be removed.
 * @throws ContainerException throws exception if the document id is incorrect or there are
 *         one or more signatures.
 */
void ASiC_E::removeDataFile(unsigned int id)
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
        THROW("Incorrect document id %u, there are only %u documents in container.", id, d->documents.size());
}

/**
 * @return returns ASiC_E container mimetype.
 */
string ASiC_E::mediaType() const
{
    return ASiC_E::ASIC_MIMETYPE;
}

/**
 * Adds signature to the container. Default profile is TM
 *
 * @param signature signature, which is added to the container.
 * @throws ContainerException throws exception if there are no documents in container.
 */
void ASiC_E::addAdESSignature(istream &sigdata)
{
    if(d->documents.empty())
        THROW("No documents in container, can not add signature.");

    try
    {
        d->signatures.push_back(new SignatureA(sigdata, this));
    }
    catch(const Exception &e)
    {
        THROW_CAUSE(e, "Failed to add signature.");
    }
}

Container* ASiC_E::openInternal(const string &path)
{
    return new ASiC_E(path);
}

/**
 * Returns signature referenced by signature id.
 *
 * @param id signature id.
 * @return returns signature referenced by signature id.
 * @throws ContainerException throws exception if the signature id is incorrect.
 */
vector<Signature *> ASiC_E::signatures() const
{
    return d->signatures;
}

/**
 * Removes signature from container by signature id.
 *
 * @param id signature's id, which will be removed.
 * @throws ContainerException throws exception if the signature id is incorrect.
 */
void ASiC_E::removeSignature(unsigned int id)
{
    if(d->signatures.size() > id)
    {
        vector<Signature*>::iterator it = (d->signatures.begin() + id);
        delete *it;
        d->signatures.erase(it);
    }
    else
        THROW("Incorrect signature id %u, there are only %u signatures in container.", id, d->signatures.size());
}

/**
 * Creates BDoc container manifest file and returns its path.
 * 
 * Note: If non-ascii characters are present in XML data, we depend on the LANG variable to be set properly
 * (see iconv --list for the list of supported encoding values for libiconv).
 *
 *
 * @return returns created manifest file path.
 * @throws IOException exception is thrown if manifest file creation failed.
 */
void ASiC_E::createManifest(ostream &os)
{
    DEBUG("ASiC_E::createManifest()");

    try
    {
        Manifest manifest;
        manifest.file_entry().push_back(File_entry("/", mediaType()));
        for(DataFile *file: d->documents)
            manifest.file_entry().push_back(File_entry(file->fileName(), file->mediaType()));

        xml_schema::NamespaceInfomap map;
        map["manifest"].name = ASiC_EPrivate::MANIFEST_NAMESPACE;
        manifest::manifest(os, manifest, map, "", xml_schema::Flags::dont_initialize);
        if(os.fail())
            THROW("Failed to create manifest XML");
    }
    catch(const xml_schema::Exception& e)
    {
        THROW("Failed to create manifest XML file. Error: %s", e.what());
    }
}

/**
 * Reads and parses container mimetype. Checks that the mimetype is supported.
 *
 * @param path path to container directory.
 * @throws IOException exception is thrown if there was error reading mimetype file from disk.
 * @throws ContainerException exception is thrown if the parsed mimetype is incorrect.
 */
void ASiC_E::readMimetype(istream &is)
{
    DEBUG("ASiC_E::readMimetype()");
    unsigned char bom[] = { 0, 0, 0 };
    is.read((char*)bom, sizeof(bom));
    // Contains UTF-16 BOM
    if((bom[0] == 0xFF && bom[1] == 0xEF) ||
       (bom[0] == 0xEF && bom[1] == 0xFF))
        THROW("Mimetype file must be UTF-8 format.");
    // does not contain UTF-8 BOM reset pos
    if(!(bom[0] == 0xEF && bom[1] == 0xBB && bom[2] == 0xBF))
        is.seekg(0, ios::beg);

    string mimetype;
    is >> mimetype;
    if(is.fail())
        THROW("Failed to read mimetype.");

    DEBUG("mimetype = '%s'", mimetype.c_str());
    if(mimetype != ASiC_E::ASIC_MIMETYPE)
        THROW("Incorrect mimetype '%s'", mimetype.c_str());

}

/**
 * Parses manifest file and checks that files described in manifest exist, also
 * checks that no extra file do exist that are not described in manifest.xml.
 *
 * Note: If non-ascii characters are present in XML data, we depend on the LANG variable to be set properly 
 * (see iconv --list for the list of supported encoding values for libiconv).
 *
 * @param path directory on disk of the BDOC container.
 * @throws IOException exception is thrown if the manifest.xml file parsing failed.
 * @throws ContainerException
 */
void ASiC_E::parseManifestAndLoadFiles(const ZipSerialize &z, const vector<string> &list)
{
    DEBUG("ASiC_E::readManifest()");

    size_t mcount = count(list.begin(), list.end(), "META-INF/manifest.xml");
    if(mcount < 1)
        THROW("Manifest file is missing");
    if(mcount > 1)
        THROW("Found multiple manifest files");

    try
    {
        stringstream manifestdata;
        z.extract("META-INF/manifest.xml", manifestdata);
        xml_schema::Properties properties;
        properties.schema_location(ASiC_EPrivate::MANIFEST_NAMESPACE,
            File::fullPathUrl(Conf::instance()->xsdPath() + "/OpenDocument_manifest.xsd"));
        unique_ptr<Manifest> manifest(manifest::manifest(manifestdata, xml_schema::Flags::dont_initialize|xml_schema::Flags::dont_validate, properties).release());

        Manifest::File_entrySequence::const_iterator iter = manifest->file_entry().begin();
        if(iter->full_path() == "/" && mediaType() != iter->media_type())
            THROW("Manifest has incorrect BDOC container media type defined '%s', expecting '%s'.", iter->media_type().c_str(), mediaType().c_str());

        set<string> manifestFiles;
        for(iter++; iter != manifest->file_entry().end(); ++iter)
        {
            DEBUG("full_path = '%s', media_type = '%s'", iter->full_path().c_str(), iter->media_type().c_str());

            if(manifestFiles.find(iter->full_path()) != manifestFiles.end())
                THROW("Manifest multiple entries defined for file '%s'.", iter->full_path().c_str());

            size_t fcount = count(list.begin(), list.end(), iter->full_path());
            if(fcount < 1)
                THROW("File described in manifest '%s' does not exist in BDOC container.", iter->full_path().c_str());
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
               file == "META-INF/manifest.xml")
                continue;

            /**
             * http://www.etsi.org/deliver/etsi_ts/102900_102999/102918/01.03.01_60/ts_102918v010301p.pdf
             * 6.2.2 Contents of Container
             * 3) The root element of each "*signatures*.xml" content shall be either:
             */
            if(file.compare(0, 9, "META-INF/") == 0 &&
               file.find("signatures") != std::string::npos)
            {
                if(count(list.begin(), list.end(), file) > 1)
                    THROW("Multiple signature files with same name found '%s'", file.c_str());
                try
                {
                    stringstream data;
                    z.extract(file, data);
                    d->signatures.push_back(new SignatureA(data, this, true));
                }
                catch(const Exception &e)
                {
                    THROW_CAUSE(e, "Failed to parse signature '%s'.", file.c_str());
                }
                continue;
            }

            if(manifestFiles.find(file) == manifestFiles.end())
                THROW("File '%s' found in BDOC container is not described in manifest.", file.c_str());
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
    catch (const xercesc::OutOfMemoryException& e)
    {
        THROW("Failed to parse manifest XML: out of memory");
    }
    catch (...)
    {
        THROW("Failed to parse manifest XML: Unknown exception");
    }
}

Signature* ASiC_E::prepareSignature(Signer *signer)
{
    if(d->documents.empty())
        THROW("No documents in container, can not sign container.");
    if(!signer)
        THROW("Null pointer in ASiC_E::sign");

    SignatureA *signature = new SignatureA(newSignatureId(), this, signer);
    d->signatures.push_back(signature);
    return signature;
}

Signature *ASiC_E::sign(Signer* signer)
{
    SignatureA *s = static_cast<SignatureA*>(prepareSignature(signer));
    try
    {
        s->setSignatureValue(signer->sign(s->signatureMethod(), s->dataToSign()));
        s->extendSignatureProfile(signer->profile().empty() ? ASiC_E::ASIC_TS_PROFILE : signer->profile());
    }
    catch(const Exception& e)
    {
        vector<Signature*>::iterator i = find(d->signatures.begin(), d->signatures.end(), s);
        if(i != d->signatures.end())
            d->signatures.erase(i);
        delete s;
        THROW_CAUSE(e, "Failed to sign BDOC container.");
    }
    return s;
}
