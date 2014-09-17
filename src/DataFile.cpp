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

#include "DataFile_p.h"

#include "log.h"
#include "crypto/Digest.h"
#include "util/File.h"

#include <fstream>

using namespace digidoc;
using namespace digidoc::util;
using namespace std;


/**
 * @class digidoc::DataFile
 *
 * @brief Data file wrapper providing methods for handling signed files or files to be signed in <code>Container</code>.
 */

/**
 * Initializes the data file object.
 *
 * @param filename name of the data file
 * @param filepath full path of the data file.
 * @param mediaType data file's media type (e.g. "application/msword" or "text/xml").
 * @param id DDoc DataFile id
 * @param digestValue DDoc container calculated digest
 */
DataFile::DataFile(istream *is, const string &filename, const string &mediatype,
                   const string &id, const vector<unsigned char> &digestValue)
    : d(new DataFilePrivate)
{
    d->is = is;
    d->id = id.empty() ? filename : id;
    d->filename = filename;
    d->mediatype = mediatype;
    d->digestValue = digestValue;
    d->is->seekg(0, istream::end);
    istream::pos_type pos = d->is->tellg();
    d->size = pos < 0 ? 0 : (unsigned long)pos;
}

/**
 * Returns data file id
 */
string DataFile::id() const
{
    return d->id;
}

/**
 * Returns data file name
 */
string DataFile::fileName() const
{
    return d->filename;
}

/**
 * Returns data file size
 */
unsigned long DataFile::fileSize() const
{
    return d->size;
}

/**
 * Returns data file's media type
 */
string DataFile::mediaType() const
{
    return d->mediatype;
}

/**
 * Calculates digest for data file. If digest is already calculated returns it,
 * otherwise calculates the digest.
 *
 * Supported uris for BDoc:
 * - http://www.w3.org/2000/09/xmldsig#sha1
 * - http://www.w3.org/2001/04/xmldsig-more#sha224
 * - http://www.w3.org/2001/04/xmlenc#sha256
 * - http://www.w3.org/2001/04/xmldsig-more#sha384
 * - http://www.w3.org/2001/04/xmlenc#sha512
 *
 * In case of DDoc files, the parameter is ignored and SHA1 hash is always returned
 *
 * @param method method uri for calculating digest.
 * @return returns calculated digest.
 * @throws Exception throws exception if the file does not exist or digest calculation fails.
 */
vector<unsigned char> DataFile::calcDigest(const string &method) const
{
    if(!d->digestValue.empty())
        return d->digestValue;
    Digest calc(method);
    calcDigest(&calc);
    return calc.result();
}

void DataFile::calcDigest(Digest *digest) const
{
    vector<unsigned char> buf(10240, 0);
    d->is->clear();
    d->is->seekg(0);
    while(*d->is)
    {
        d->is->read((char*)&buf[0], buf.size());
        if(d->is->gcount() > 0)
            digest->update(&buf[0], (unsigned long)d->is->gcount());
    }
}

/**
 * Saves a copy of the data file as file specified by path.
 * @param path full file path, where the data file should be saved to. If file exists, it is overwritten
 * @throws Exception if part of path does not exist or path is existing directory (without file name)
 */
void DataFile::saveAs(const string& path) const
{
    ofstream ofs(File::encodeName(path).c_str(), ofstream::binary);
    saveAs(ofs);
    ofs.close();
}

/**
 * Saves a copy of the data file as file specified by stream.
 * @param os stream where data is written
 */
void DataFile::saveAs(ostream &os) const
{
    d->is->clear();
    d->is->seekg(0);
    os << d->is->rdbuf();
}
