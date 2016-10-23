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
#include "File.h"
#include "ZipSerialize.h"

#include "log.h"

#include <sstream>

using namespace digidoc::util::asic;
using namespace std;

/**
 * Read mimetype from input stream.
 *
 * @param is input stream.
 * @param filename name of the stream
 * @throws IOException exception is thrown if there was error reading text file from disk.
 * @throws Exception exception is thrown if the text cannot be read because of format error.
 */
string digidoc::util::asic::readMimetype(istream &is)
{
    DEBUG("readMimetype()");
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

bool digidoc::util::asic::isTimestampedASiC_S(const vector<string> &list)
{
    DEBUG("isASiCSContainer()");
    bool isASiCS = false;

    auto dataFiles = 0;
    auto hasTimestamp = false;

    // container has only one file in root folder and has a timestamp
    for(const string &file: list)
    {
        const auto directory = File::directory(file);
        if(directory.empty() || directory == "/" || directory == "./")
        {
            dataFiles++;
        }

        if(file == "META-INF/timestamp.tst")
        {
            hasTimestamp = true;
        }
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
ASiCFormat digidoc::util::asic::detectContainerFormat(const string &path)
{
    DEBUG("isASiCSContainer(path = '%s')", path.c_str());
    auto containerFormat = ASiCFormat::Unknown;

    const auto extension = util::File::fileExtension(path);
    if(extension == ASICE_EXTENSION || extension == ASICE_EXTENSION_ABBR || extension == BDOC_EXTENSION)
    {
        containerFormat = ASiCFormat::Extended;
    }
    else if(extension == ASICS_EXTENSION || extension == ASICS_EXTENSION_ABBR)
    {
        containerFormat = ASiCFormat::Simple;
    }
    else
    {
        DEBUG("Check if ASiC/zip containter");
        try
        {
            ZipSerialize z(path, false);

            vector<string> list = z.list();
            if(std::find(list.begin(), list.end(), "mimetype") != list.end())
            {
                stringstream iss;
                z.extract("mimetype", iss);
                string mimetype = readMimetype(iss);
                if(mimetype == ASICS_MIMETYPE)
                {
                    containerFormat = ASiCFormat::Simple;
                }
                else if(mimetype == ASICE_MIMETYPE)
                {
                    containerFormat = ASiCFormat::Extended;
                }
            }

            if(containerFormat == ASiCFormat::Unknown && isTimestampedASiC_S(list))
            {
                containerFormat = ASiCFormat::Simple;
            }

        }
        catch(const Exception &)
        {
            // Ignore the exception: not ASiC/zip document
        }

    }

    DEBUG("ASiC Format: %d", containerFormat);
    return containerFormat;
}
