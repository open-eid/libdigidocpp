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

#include "BDoc.h"

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

#include <fstream>
#include <set>

using namespace digidoc;
using namespace digidoc::util;
using namespace std;

namespace digidoc
{
class BDocPrivate
{
public:
    BDocPrivate(): mimetype(BDoc::ASIC_MIMETYPE) {}
    ZipSerialize::Properties propertie(const string &file)
    {
        map<string, ZipSerialize::Properties>::const_iterator i = properties.find(file);
        if(i != properties.end())
            return i->second;

        time_t t = time(0);
        tm *filetime = gmtime(&t);
        ZipSerialize::Properties prop = { appInfo(), *filetime };
        return properties[file] = prop;
    }

    static const string MANIFEST_NAMESPACE;

    string mimetype, path;
    DataFileList documents;
    vector<Signature*> signatures;
    map<string, ZipSerialize::Properties> properties;
};
}

const string BDoc::ASIC_MIMETYPE = "application/vnd.etsi.asic-e+zip";
const string BDoc::BDOC_MIMETYPE = "application/vnd.bdoc-1.0";
const string BDocPrivate::MANIFEST_NAMESPACE = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";

const string BDoc::BES_PROFILE = "BES";
const string BDoc::EPES_PROFILE = "EPES";
const string BDoc::ASIC_TM_PROFILE = "time-mark";
const string BDoc::ASIC_TS_PROFILE = "time-stamp";
const string BDoc::ASIC_TSA_PROFILE = ASIC_TS_PROFILE + "-archive";
const string BDoc::ASIC_TMA_PROFILE = ASIC_TM_PROFILE + "-archive";

/**
 * Initialize BDOC container.
 */
BDoc::BDoc()
 : d(new BDocPrivate)
{
}

/**
 * Opens BDOC container from a file
 */

BDoc::BDoc(const string &path)
 : d(new BDocPrivate)
{
    DEBUG("BDoc::BDoc(path = '%s')", path.c_str());
    ZipSerialize z(d->path = path, false);

    vector<string> list = z.list();
    if(list.empty())
        THROW("Failed to parse container");

    for(const string &file: list)
        d->properties[file] = z.properties(file);

    stringstream mimetype;
    z.extract(list.front(), mimetype);
    readMimetype(mimetype);
    if(d->mimetype == BDOC_MIMETYPE)
        THROW("BDoc1 container altering is unsupported");
    parseManifestAndLoadFiles(z, list);
}

/**
 * Releases resources.
 */
BDoc::~BDoc()
{
    while(!d->signatures.empty())
    {
        delete (d->signatures.back());
        d->signatures.pop_back();
    }
    delete d;
}

/**
 * Saves the container using the <code>serializer</code> implementation provided in
 * <code>readFrom()</code> method.
 *
 * @throws IOException is thrown if there was a failure saving BDOC container. For example added
 *         document does not exist.
 * @throws ContainerException is thrown if BDoc class is not correctly initialized.
 */
void BDoc::save(const string &path)
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

    for(DataFileList::const_iterator iter = d->documents.begin(); iter != d->documents.end(); ++iter)
        s.addFile(iter->fileName(), *iter->d->is, d->propertie(iter->fileName()));

    unsigned int i = 0;
    for(vector<Signature*>::const_iterator iter = d->signatures.begin(); iter != d->signatures.end(); ++iter)
    {
        string file = Log::format("META-INF/signatures%u.xml", i++);
        SignatureBES *signature = static_cast<SignatureBES*>(*iter);

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
void BDoc::addDataFile(const string &path, const string &mediaType)
{
    if(!d->signatures.empty())
        THROW("Can not add document to container which has signatures, remove all signatures before adding new document.");

    if(!File::fileExists(path))
        THROW("Document file '%s' does not exist.", path.c_str());

    for(DataFileList::const_iterator iter = d->documents.begin(); iter != d->documents.end(); ++iter)
    {
        if(path.compare(iter->fileName()) == 0)
            THROW("Document with same file name '%s' already exists '%s'.", path.c_str(), iter->fileName().c_str());
    }

    tm *filetime = File::modifiedTime(path);
    ZipSerialize::Properties prop = { appInfo(), *filetime };
    d->properties[File::fileName(path)] = prop;
#if 0
    d->documents.push_back(DataFile(new std::ifstream(File::encodeName(path).c_str(), std::ifstream::binary),
        File::fileName(path), mediaType));
#else
    std::ifstream file(File::encodeName(path).c_str(), std::ifstream::binary);
    stringstream *data = new stringstream;
    if(file)
        *data << file.rdbuf();
    file.close();
    d->documents.push_back(DataFile(data, File::fileName(path), mediaType));
#endif
}

void BDoc::addDataFile(istream *is, const string &fileName, const string &mediaType)
{
    if(!d->signatures.empty())
        THROW("Can not add document to container which has signatures, remove all signatures before adding new document.");

    for(DataFileList::const_iterator iter = d->documents.begin(); iter != d->documents.end(); ++iter)
    {
        if(fileName == iter->fileName())
            THROW("Document with same file name '%s' already exists '%s'.", fileName.c_str(), iter->fileName().c_str());
    }

    d->documents.push_back(DataFile(is, fileName, mediaType));
}

Container* BDoc::createInternal(const string &path)
{
    BDoc *doc = new BDoc();
    doc->d->path = path;
    return doc;
}

/**
 * Returns document referenced by document id.
 *
 * @return returns dataFiles.
 */
DataFileList BDoc::dataFiles() const
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
void BDoc::removeDataFile(unsigned int id)
{
    if(!d->signatures.empty())
        THROW("Can not remove document from container which has signatures, remove all signatures before removing document.");

    if(d->documents.size() > id)
        d->documents.erase(d->documents.begin() + id);
    else
        THROW("Incorrect document id %u, there are only %u documents in container.", id, d->documents.size());
}

/**
 * @return returns BDoc container mimetype.
 */
string BDoc::mediaType() const
{
    return d->mimetype;
}

/**
 * Adds signature to the container. Default profile is TM
 *
 * @param signature signature, which is added to the container.
 * @throws ContainerException throws exception if there are no documents in container.
 */
void BDoc::addRawSignature(istream &sigdata)
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

Container* BDoc::openInternal(const string &path)
{
    return new BDoc(path);
}

/**
 * Returns signature referenced by signature id.
 *
 * @param id signature id.
 * @return returns signature referenced by signature id.
 * @throws ContainerException throws exception if the signature id is incorrect.
 */
SignatureList BDoc::signatures() const
{
    return d->signatures;
}

/**
 * Removes signature from container by signature id.
 *
 * @param id signature's id, which will be removed.
 * @throws ContainerException throws exception if the signature id is incorrect.
 */
void BDoc::removeSignature(unsigned int id)
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
void BDoc::createManifest(ostream &os)
{
    DEBUG("BDoc::createManifest()");

    try
    {
        manifest::Manifest manifest;
        manifest.file_entry().push_back(manifest::File_entry("/", mediaType()));
        for(DataFileList::const_iterator iter = d->documents.begin(); iter != d->documents.end(); ++iter)
            manifest.file_entry().push_back(manifest::File_entry(iter->fileName(), iter->mediaType()));

        xml_schema::NamespaceInfomap map;
        map["manifest"].name = BDocPrivate::MANIFEST_NAMESPACE;
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
void BDoc::readMimetype(istream &is)
{
    DEBUG("BDoc::readMimetype()");
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
    if(mimetype == BDoc::ASIC_MIMETYPE || mimetype == BDoc::BDOC_MIMETYPE)
        d->mimetype = mimetype;
    else
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
void BDoc::parseManifestAndLoadFiles(const ZipSerialize &z, const vector<string> &list)
{
    DEBUG("BDoc::readManifest()");

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
        properties.schema_location(BDocPrivate::MANIFEST_NAMESPACE,
            File::fullPathUrl(Conf::instance()->xsdPath() + "/OpenDocument_manifest.xsd"));
        unique_ptr<manifest::Manifest> manifest(manifest::manifest(manifestdata, xml_schema::Flags::dont_initialize, properties).release());

        manifest::Manifest::File_entrySequence::const_iterator iter = manifest->file_entry().begin();
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
#if 0
            fstream *data = new fstream(File::encodeName(File::tempFileName()).c_str(), fstream::binary);
#else
            stringstream *data = new stringstream;
#endif
            z.extract(iter->full_path(), *data);
            d->documents.push_back(DataFile(data, iter->full_path(), iter->media_type()));
        }

        for(vector<string>::const_iterator iter = list.begin(); iter != list.end(); ++iter)
        {
            if(*iter == "mimetype" ||
               *iter == "META-INF/" ||
               *iter == "META-INF/manifest.xml")
                continue;

            if(d->mimetype == BDoc::ASIC_MIMETYPE &&
               iter->compare(0, 19, "META-INF/signatures") == 0)
            {
                if(count(list.begin(), list.end(), *iter) > 1)
                    THROW("Multiple signature files with same name found '%s'", iter->c_str());
                try
                {
                    stringstream data;
                    z.extract(*iter, data);
                    d->signatures.push_back(new SignatureA(data, this));
                }
                catch(const Exception &e)
                {
                    THROW_CAUSE(e, "Failed to parse signature '%s'.", iter->c_str());
                }
                continue;
            }

            if(manifestFiles.find(*iter) == manifestFiles.end())
                THROW("File '%s' found in BDOC container is not described in manifest.", iter->c_str());
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
}

/**
 * Signs all documents in container.
 *
 * @param signer signer implementation.
 * @throws ContainerException exception is throws if signing the BDCO container failed.
 */
Signature *BDoc::sign(Signer* signer)
{
    if(d->documents.empty())
        THROW("No documents in container, can not sign container.");
    if (!signer)
        THROW("Null pointer in BDoc::sign");

    SignatureA *signature = new SignatureA(newSignatureId(), this);
    try
    {
        string digestMethod = Conf::instance()->digestUri();
        for(const DataFile &f: d->documents)
        {
            string id = signature->addReference(File::toUriPath(f.fileName()), digestMethod, f.calcDigest(digestMethod), "");
            signature->addDataObjectFormat("#" + id, f.mediaType());
        }

        vector<unsigned char> digest = signature->prepareSignedInfo(signer); // needs to be here to select also signatureMethod
        signature->setSignatureValue(signer->sign(signature->signatureMethod(), digest));
        signature->extendTo(signer->profile().empty() ? BDoc::ASIC_TS_PROFILE : signer->profile());
    }
    catch(const Exception& e)
    {
        delete signature;
        THROW_CAUSE(e, "Failed to sign BDOC container.");
    }

    d->signatures.push_back(signature);
    return signature;
}
