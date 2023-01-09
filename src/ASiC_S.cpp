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

#include "SignatureTST.h"
#include "crypto/Digest.h"
#include "util/File.h"
#include "util/log.h"
#include "util/ZipSerialize.h"

#include <algorithm>
#include <fstream>
#include <sstream>

using namespace digidoc;
using namespace digidoc::util;
using namespace std;

/**
 * Initialize ASiCS container.
 */
ASiC_S::ASiC_S(): ASiContainer(MIMETYPE_ASIC_S)
{
}

/**
 * Opens ASiC-S container from a file
 */
ASiC_S::ASiC_S(const string &path): ASiContainer(MIMETYPE_ASIC_S)
{
    auto z = load(path, false, {MIMETYPE_ASIC_S});
    loadContainer(*z);
}

void ASiC_S::save(const string & /*path*/)
{
    THROW("Not implemented.");
}

void ASiC_S::addDataFile(const string &path, const string &mediaType)
{
    if(!dataFiles().empty())
        THROW("Can not add document to ASiC-S container which already contains a document.");
        
    ASiContainer::addDataFile(path, mediaType);
}

void ASiC_S::addDataFile(unique_ptr<istream> is, const string &fileName, const string &mediaType)
{
    if(!dataFiles().empty())
        THROW("Can not add document to ASiC-S container which already contains a document.");

    ASiContainer::addDataFile(move(is), fileName, mediaType);
}

unique_ptr<Container> ASiC_S::createInternal(const string & /*path*/)
{
    return {};
}

void ASiC_S::addAdESSignature(istream & /*signature*/)
{
    THROW("Not implemented.");
}

unique_ptr<Container> ASiC_S::openInternal(const string &path)
{
    if (!isContainerSimpleFormat(path))
        return nullptr;
    DEBUG("ASiC_S::openInternal(%s)", path.c_str());
    return unique_ptr<Container>(new ASiC_S(path));
}

void ASiC_S::extractTimestamp(const ZipSerialize &z)
{
    addSignature(make_unique<SignatureTST>(dataStream("META-INF/timestamp.tst", z), this));
}

/**
 * Load container (datafile and timestamp).
 *
 * @param z Zip stream.
 * @param list List of files contained in the container.
 * @throws IOException exception is thrown if the manifest.xml file parsing failed.
 * @throws ContainerException
 */
void ASiC_S::loadContainer(const ZipSerialize &z)
{
    DEBUG("ASiC_S::loadFileAndTimestamp()");
    const string metaInf = "META-INF/";
    const vector<string> &list = z.list();
    int files = 0;

    for(const string &file: list)
    {
        if(file == "mimetype" ||
           file.substr(0, metaInf.size()) == metaInf)
            continue;

        const auto directory = File::directory(file);
        if(directory.empty() || directory == "/" || directory == "./")
        {
            if(files > 0)
            {
                THROW("ASiC-S container contains more than one data objects.");
            }
            ASiContainer::addDataFile(dataStream(file, z), file, "application/octet-stream");
            files++;
        }
    }

    if(files == 0)
    {
        THROW("ASiC-S container does not contain any data objects.");
    }

    extractTimestamp(z);
}

Signature* ASiC_S::prepareSignature(Signer * /*signer*/)
{
    THROW("Not implemented.");
}

Signature *ASiC_S::sign(Signer * /*signer*/)
{
    THROW("Not implemented.");
}


bool ASiC_S::isTimestampedASiC_S(const vector<string> &list)
{
    DEBUG("isTimestampedASiC_S()");
    bool isASiCS = false;
    
    auto dataFiles = 0;
    auto hasTimestamp = false;
    
    // container has only one file in root folder and has a timestamp
    for(const string &file: list)
    {
        const auto directory = File::directory(file);
        if(directory.empty() || directory == "/" || directory == "./")
            dataFiles++;
        if(file == "META-INF/timestamp.tst")
            hasTimestamp = true;
    }

    isASiCS = hasTimestamp && (dataFiles == 1);

    DEBUG("ASiCS Container: %s", isASiCS ? "yes" : "no");
    return isASiCS;
}

/**
 * Detect ASiC format based on file extentions, mimetype or zip contents.<br/>
 * Container format is simple (ASiC-S) or extended (ASiC-E).
 *
 * @param path Path of the container.
 * @throws Exception
 */
bool ASiC_S::isContainerSimpleFormat(const string &path)
{
    DEBUG("isContainerSimpleFormat(path = '%s')", path.c_str());
    const auto extension = util::File::fileExtension(path);
    if(extension == ASICE_EXTENSION || extension == ASICE_EXTENSION_ABBR ||
       extension == BDOC_EXTENSION)
        return false;
    if(extension == ASICS_EXTENSION || extension == ASICS_EXTENSION_ABBR)
        return true;

    DEBUG("Check if ASiC/zip containter");
    try
    {
        ZipSerialize z(path, false);
        vector<string> list = z.list();
        if(find(list.begin(), list.end(), "mimetype") != list.end())
        {
            stringstream iss;
            z.extract("mimetype", iss);
            if(readMimetype(iss) == MIMETYPE_ASIC_S)
                return true;
        }
        if(isTimestampedASiC_S(list))
            return true;
    }
    catch(const Exception &)
    {
        // Ignore the exception: not ASiC/zip document
    }

    return false;
}
