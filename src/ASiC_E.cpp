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
#include "crypto/Digest.h"
#include "crypto/Signer.h"
#include "util/File.h"
#include "util/log.h"
#include "util/ZipSerialize.h"
#include "xml/OpenDocument_manifest.hxx"
#include "xml/SecureDOMParser.h"

#include <xercesc/util/OutOfMemoryException.hpp>

#include <fstream>
#include <set>

using namespace digidoc;
using namespace digidoc::util;
using namespace std;
using namespace manifest;

const string ASiC_E::BES_PROFILE = "BES";
const string ASiC_E::EPES_PROFILE = "EPES";
const string ASiC_E::ASIC_TM_PROFILE = "time-mark";
const string ASiC_E::ASIC_TS_PROFILE = "time-stamp";
const string ASiC_E::ASIC_TSA_PROFILE = ASIC_TS_PROFILE + "-archive";
const string ASiC_E::ASIC_TMA_PROFILE = ASIC_TM_PROFILE + "-archive";
const string ASiC_E::MANIFEST_NAMESPACE = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";

class ASiC_E::Private
{
public:
    vector<DataFile*> metadata;
};

/**
 * Initialize BDOC container.
 */
ASiC_E::ASiC_E()
    : ASiContainer(MIMETYPE_ASIC_E)
    , d(make_unique<Private>())
{
}

/**
 * Opens BDOC container from a file
 */
ASiC_E::ASiC_E(const string &path)
    : ASiContainer(MIMETYPE_ASIC_E)
    , d(make_unique<Private>())
{
    auto zip = load(path, true, {MIMETYPE_ASIC_E, MIMETYPE_ADOC});
    parseManifestAndLoadFiles(*zip);
}

ASiC_E::~ASiC_E()
{
    for_each(d->metadata.cbegin(), d->metadata.cend(), std::default_delete<DataFile>());
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
void ASiC_E::save(const string &path)
{
    if(dataFiles().empty())
        THROW("Can not save, container is empty.");
    if(mediaType() != MIMETYPE_ASIC_E)
        THROW("'%s' format is not supported", mediaType().c_str());

    if(!path.empty())
        zpath(path);
    ZipSerialize s(zpath(), true);

    stringstream mimetype;
    mimetype << mediaType();
    s.addFile("mimetype", mimetype, zproperty("mimetype"), ZipSerialize::DontCompress);

    stringstream manifest;
    createManifest(manifest);
    s.addFile("META-INF/manifest.xml", manifest, zproperty("META-INF/manifest.xml"));

    for(const DataFile *file: dataFiles())
        s.addFile(file->fileName(), *(static_cast<const DataFilePrivate*>(file)->m_is.get()), zproperty(file->fileName()));

    unsigned int i = 0;
    for(Signature *iter: signatures())
    {
        string file = Log::format("META-INF/signatures%u.xml", i++);
        SignatureXAdES_B *signature = static_cast<SignatureXAdES_B*>(iter);

        stringstream ofs;
        signature->saveToXml(ofs);
        s.addFile(file, ofs, zproperty(file));
    }
}

unique_ptr<Container> ASiC_E::createInternal(const string &path)
{
    DEBUG("ASiC_E::createInternal(%s)", path.c_str());
    unique_ptr<ASiC_E> doc = unique_ptr<ASiC_E>(new ASiC_E);
    doc->zpath(path);
    return doc;
}

/**
 * Adds signature to the container. Default profile is TM
 *
 * @param sigdata signature, which is added to the container.
 * @throws Exception throws exception if there are no documents in container.
 */
void ASiC_E::addAdESSignature(istream &sigdata)
{
    if(dataFiles().empty())
        THROW("No documents in container, can not add signature.");
    if(mediaType() != MIMETYPE_ASIC_E)
        THROW("'%s' format is not supported", mediaType().c_str());

    try
    {
        addSignature(new SignatureXAdES_LTA(sigdata, this));
    }
    catch(const Exception &e)
    {
        THROW_CAUSE(e, "Failed to add signature.");
    }
}

unique_ptr<Container> ASiC_E::openInternal(const string &path)
{
    DEBUG("ASiC_E::openInternal(%s)", path.c_str());
    return unique_ptr<Container>(new ASiC_E(path));
}

/**
 * Creates BDoc container manifest file and returns its path.
 * 
 * Note: If non-ascii characters are present in XML data, we depend on the LANG variable to be set properly
 * (see iconv --list for the list of supported encoding values for libiconv).
 *
 *
 * @return returns created manifest file path.
 * @throws Exception exception is thrown if manifest file creation failed.
 */
void ASiC_E::createManifest(ostream &os)
{
    DEBUG("ASiC_E::createManifest()");

    try
    {
        Manifest manifest;
        manifest.file_entry().push_back({"/", mediaType()});
        for(const DataFile *file: dataFiles())
            manifest.file_entry().push_back({file->fileName(), file->mediaType()});

        xml_schema::NamespaceInfomap map;
        map["manifest"].name = ASiC_E::MANIFEST_NAMESPACE;
        manifest::manifest(os, manifest, map, {}, xml_schema::Flags::dont_initialize);
        if(os.fail())
            THROW("Failed to create manifest XML");
    }
    catch(const xercesc::DOMException &e)
    {
        try {
            string result = xsd::cxx::xml::transcode<char>(e.getMessage());
            THROW("Failed to create manifest XML file. Error: %s", result.c_str());
        } catch(const xsd::cxx::xml::invalid_utf16_string & /* ex */) {
            THROW("Failed to create manifest XML file.");
        }
    }
    catch(const xml_schema::Exception &e)
    {
        THROW("Failed to create manifest XML file. Error: %s", e.what());
    }
}

/**
 * Parses manifest file and checks that files described in manifest exist, also
 * checks that no extra file do exist that are not described in manifest.xml.
 *
 * Note: If non-ascii characters are present in XML data, we depend on the LANG variable to be set properly 
 * (see iconv --list for the list of supported encoding values for libiconv).
 *
 * @param path directory on disk of the BDOC container.
 * @throws Exception exception is thrown if the manifest.xml file parsing failed.
 */
void ASiC_E::parseManifestAndLoadFiles(const ZipSerialize &z)
{
    DEBUG("ASiC_E::readManifest()");

    const vector<string> &list = z.list();
    size_t mcount = size_t(count(list.cbegin(), list.cend(), "META-INF/manifest.xml"));
    if(mcount < 1)
        THROW("Manifest file is missing");
    if(mcount > 1)
        THROW("Found multiple manifest files");

    try
    {
        stringstream manifestdata;
        z.extract("META-INF/manifest.xml", manifestdata);
        xml_schema::Properties p;
        p.schema_location(ASiC_E::MANIFEST_NAMESPACE,
            File::fullPathUrl(Conf::instance()->xsdPath() + "/OpenDocument_manifest.xsd"));
        unique_ptr<xercesc::DOMDocument> doc = SecureDOMParser(p.schema_location(), true).parseIStream(manifestdata);
        unique_ptr<Manifest> manifest = manifest::manifest(*doc, {}, p);

        set<string> manifestFiles;
        bool mimeFound = false;
        for(const File_entry &file: manifest->file_entry())
        {
            DEBUG("full_path = '%s', media_type = '%s'", file.full_path().c_str(), file.media_type().c_str());

            if(manifestFiles.find(file.full_path()) != manifestFiles.end())
                THROW("Manifest multiple entries defined for file '%s'.", file.full_path().c_str());

            // ODF does not specify that mimetype should be first in manifest
            if(file.full_path() == "/")
            {
                if(mediaType() != file.media_type())
                    THROW("Manifest has incorrect container media type defined '%s', expecting '%s'.", file.media_type().c_str(), mediaType().c_str());
                mimeFound = true;
                continue;
            }
            if(file.full_path().back() == '/') // Skip Directory entries
                continue;

            size_t fcount = size_t(count(list.cbegin(), list.cend(), file.full_path()));
            if(fcount < 1)
                THROW("File described in manifest '%s' does not exist in container.", file.full_path().c_str());
            if(fcount > 1)
                THROW("Found multiple references of file '%s' in zip container.", file.full_path().c_str());

            manifestFiles.insert(file.full_path());
            if(mediaType() == MIMETYPE_ADOC &&
               (file.full_path().compare(0, 9, "META-INF/") == 0 ||
                file.full_path().compare(0, 9, "metadata/") == 0))
                d->metadata.push_back(new DataFilePrivate(dataStream(file.full_path(), z), file.full_path(), file.media_type()));
            else
                addDataFilePrivate(dataStream(file.full_path(), z), file.full_path(), file.media_type());
        }
        if(!mimeFound)
            THROW("Manifest is missing mediatype file entry.");

        for(const string &file: list)
        {
            /**
             * http://www.etsi.org/deliver/etsi_ts/102900_102999/102918/01.03.01_60/ts_102918v010301p.pdf
             * 6.2.2 Contents of Container
             * 3) The root element of each "*signatures*.xml" content shall be either:
             */
            if(file.compare(0, 9, "META-INF/") == 0 &&
               file.find("signatures") != string::npos)
            {
                if(count(list.begin(), list.end(), file) > 1)
                    THROW("Multiple signature files with same name found '%s'", file.c_str());
                try
                {
                    stringstream data;
                    z.extract(file, data);
                    addSignature(new SignatureXAdES_LTA(data, this, true));
                }
                catch(const Exception &e)
                {
                    THROW_CAUSE(e, "Failed to parse signature '%s'.", file.c_str());
                }
                continue;
            }

            if(file == "mimetype" || file.compare(0, 8,"META-INF") == 0)
                continue;
            if(manifestFiles.find(file) == manifestFiles.end())
                THROW("File '%s' found in container is not described in manifest.", file.c_str());
        }
    }
    catch(const xercesc::DOMException &e)
    {
        try {
            string result = xsd::cxx::xml::transcode<char>(e.getMessage());
            THROW("Failed to create manifest XML file. Error: %s", result.c_str());
        } catch(const xsd::cxx::xml::invalid_utf16_string & /* ex */) {
            THROW("Failed to create manifest XML file.");
        }
    }
    catch(const xsd::cxx::xml::invalid_utf16_string &)
    {
        THROW("Failed to parse manifest XML: %s", Conf::instance()->xsdPath().c_str());
    }
    catch(const xsd::cxx::xml::properties<char>::argument & /* e */)
    {
        THROW("Failed to parse manifest XML: %s", Conf::instance()->xsdPath().c_str());
    }
    catch(const xsd::cxx::tree::unexpected_element<char> &e)
    {
        THROW("Failed to parse manifest XML: %s %s %s", Conf::instance()->xsdPath().c_str(), e.expected_name().c_str(), e.encountered_name().c_str());
    }
    catch(const xml_schema::Exception& e)
    {
        THROW("Failed to parse manifest XML: %s (xsd path: %s)", e.what(), Conf::instance()->xsdPath().c_str());
    }
    catch(const xercesc::OutOfMemoryException &)
    {
        THROW("Failed to parse manifest XML: out of memory");
    }
    catch(const Exception &e)
    {
        THROW_CAUSE(e, "Failed to parse manifest");
    }
    catch(...)
    {
        THROW("Failed to parse manifest XML: Unknown exception");
    }
}

Signature* ASiC_E::prepareSignature(Signer *signer)
{
    if(mediaType() != MIMETYPE_ASIC_E)
        THROW("'%s' format is not supported", mediaType().c_str());
    if(dataFiles().empty())
        THROW("No documents in container, can not sign container.");
    if(!signer)
        THROW("Null pointer in ASiC_E::sign");
    SignatureXAdES_LTA *signature = new SignatureXAdES_LTA(newSignatureId(), this, signer);
    addSignature(signature);
    return signature;
}

Signature *ASiC_E::sign(Signer* signer)
{
    SignatureXAdES_LTA *s = static_cast<SignatureXAdES_LTA*>(prepareSignature(signer));
    try
    {
        s->setSignatureValue(signer->sign(s->signatureMethod(), s->dataToSign()));
        s->extendSignatureProfile(signer->profile().empty() ? ASiC_E::ASIC_TS_PROFILE : signer->profile());
    }
    catch(const Exception& e)
    {
        deleteSignature(s);
        THROW_CAUSE(e, "Failed to sign container.");
    }
    return s;
}
