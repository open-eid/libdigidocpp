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
#include "SignatureXAdES_LTA.h"
#include "util/File.h"
#include "util/log.h"
#include "util/ZipSerialize.h"

#include <algorithm>
#include <sstream>

using namespace digidoc;
using namespace digidoc::util;
using namespace std;

/**
 * Initialize ASiCS container.
 */
ASiC_S::ASiC_S(): ASiContainer(MIMETYPE_ASIC_S)
{}

/**
 * Opens ASiC-S container from a file
 */
ASiC_S::ASiC_S(const string &path): ASiContainer(MIMETYPE_ASIC_S)
{
    auto *z = load(path, false, {mediaType()});
    static const string_view metaInf = "META-INF/";

    for(const string &file: z->list())
    {
        if(file == "mimetype" ||
            (metaInf.size() < file.size() && file.compare(0, metaInf.size(), metaInf) == 0))
        {
            if(file == "META-INF/timestamp.tst")
            {
                if(!signatures().empty())
                    THROW("Can not add signature to ASiC-S container which already contains a signature.");
                addSignature(make_unique<SignatureTST>(*z->stream(file), this));
            }
            if(file == "META-INF/signatures.xml")
            {
                if(!signatures().empty())
                    THROW("Can not add signature to ASiC-S container which already contains a signature.");
                auto signatures = make_shared<Signatures>(*z->stream(file), this);
                for(size_t i = 0, count = signatures->count(); i < count; ++i)
                    addSignature(make_unique<SignatureXAdES_LTA>(signatures, i, this));
            }
            continue;
        }

        const auto directory = File::directory(file);
        if(directory.empty() || directory == "/" || directory == "./")
        {
            if(!dataFiles().empty())
                THROW("Can not add document to ASiC-S container which already contains a document.");
            addDataFilePrivate(file, "application/octet-stream");
        }
    }

    if(dataFiles().empty())
        THROW("ASiC-S container does not contain any data objects.");
    if(signatures().empty())
        THROW("ASiC-S container does not contain any signatures.");
}

void ASiC_S::save(const string & /*path*/)
{
    THROW("Not implemented.");
}

unique_ptr<Container> ASiC_S::createInternal(const string & /*path*/)
{
    return {};
}

void ASiC_S::addAdESSignature(istream & /*signature*/)
{
    THROW("Not implemented.");
}

unique_ptr<Container> ASiC_S::openInternal(const string &path, ContainerOpenCB * /*cb*/)
{
    if (!isContainerSimpleFormat(path))
        return {};
    DEBUG("ASiC_S::openInternal(%s)", path.c_str());
    return unique_ptr<Container>(new ASiC_S(path));
}

Signature* ASiC_S::prepareSignature(Signer * /*signer*/)
{
    THROW("Not implemented.");
}

Signature *ASiC_S::sign(Signer * /*signer*/)
{
    THROW("Not implemented.");
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
    if(util::File::fileExtension(path, {"asice", "sce", "bdoc"}))
        return false;
    if(util::File::fileExtension(path, {"asics", "scs"}))
        return true;
    DEBUG("Check if ASiC/zip containter");
    try
    {
        ZipSerialize z(path, false);
        vector<string> list = z.list();
        return !list.empty() && list.front() == "mimetype" && readMimetype(z) == MIMETYPE_ASIC_S;
    }
    catch(const Exception &)
    {
        // Ignore the exception: not ASiC/zip document
    }
    return false;
}
