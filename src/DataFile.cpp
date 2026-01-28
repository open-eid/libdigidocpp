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

#include "crypto/Digest.h"
#include "util/File.h"
#include "util/log.h"
#include "util/ZipSerialize.h"

#include <array>
#include <fstream>
#include <sstream>

using namespace digidoc;
using namespace digidoc::util;
using namespace std;

/**
 * @class digidoc::DataFile
 *
 * @brief Data file wrapper providing methods for handling signed files or files to be signed in <code>Container</code>.
 */
/**
 * @fn digidoc::DataFile::calcDigest
 * Calculates digest for data file. If digest is already calculated returns it,
 * otherwise calculates the digest.
 *
 * Supported uris:
 * - http://www.w3.org/2000/09/xmldsig#sha1
 * - http://www.w3.org/2001/04/xmldsig-more#sha224
 * - http://www.w3.org/2001/04/xmlenc#sha256
 * - http://www.w3.org/2001/04/xmldsig-more#sha384
 * - http://www.w3.org/2001/04/xmlenc#sha512
 *
 * @param method method uri for calculating digest.
 * @return returns calculated digest value.
 * @throws Exception throws exception if the file does not exist or digest calculation fails.
 */
/**
 * @fn digidoc::DataFile::id
 * Returns data file id
 */
/**
 * @fn digidoc::DataFile::fileName
 * Returns data file name
 */
/**
 * @fn digidoc::DataFile::fileSize
 * Returns data file size
 */
/**
 * @fn digidoc::DataFile::mediaType
 * Returns data file's media type
 */
/**
 * @fn void digidoc::DataFile::saveAs(const std::string &path) const
 *
 * Saves a copy of the data file as file specified by path.
 * @param path full file path, where the data file should be saved to. If file exists, it is overwritten
 * @throws Exception if part of path does not exist or path is existing directory (without file name)
 */
/**
 * @fn void digidoc::DataFile::saveAs(std::ostream &os) const
 * Saves a copy of the data file as file specified by stream.
 * @param os stream where data is written
 */

DataFile::DataFile() = default;
DataFile::~DataFile() = default;

struct DataFilePrivate::Private {
    optional<unsigned long> size;
};

DataFilePrivate::DataFilePrivate(unique_ptr<istream> &&is, string filename, string mediatype, string id)
    : d(make_unique<Private>())
    , m_is(std::move(is))
    , m_id(std::move(id))
    , m_filename(std::move(filename))
    , m_mediatype(std::move(mediatype))
{}

DataFilePrivate::DataFilePrivate(const ZipSerialize &z, string filename, string mediatype)
    : d(make_unique<Private>())
    , m_filename(std::move(filename))
    , m_mediatype(std::move(mediatype))
{
    auto r = z.read(m_filename);
    d->size.emplace((unsigned long)r.size);
    if(r.size > MAX_MEM_FILE)
    {
        auto fs = make_unique<fstream>(util::File::tempFileName(), fstream::in|fstream::out|fstream::binary|fstream::trunc);
        if(!fs->is_open())
            THROW("Failed to open destination file");
        array<char,10240> buf{};
        for(size_t size = 0, currentStreamSize = 0;
             (size = r(buf.data(), buf.size())) > 0; currentStreamSize += size)
        {
            if(!fs->write(buf.data(), size))
                THROW("Failed to write '%s' data to stream. Stream size: %d", m_filename.c_str(), currentStreamSize);
        }
        m_is = std::move(fs);
    }
    else
        m_is = make_unique<stringstream>(r.operator string());
}

DataFilePrivate::~DataFilePrivate() noexcept = default;

void DataFilePrivate::digest(const Digest &digest) const
{
    m_is->clear();
    m_is->seekg(0);
    digest.update(*m_is);
}

vector<unsigned char> DataFilePrivate::calcDigest(const string &method) const
{
    Digest d(method);
    digest(d);
    return d.result();
}

unsigned long DataFilePrivate::fileSize() const
{
    if(d->size.has_value())
        return d->size.value();
    m_is->clear();
    m_is->seekg(0, istream::end);
    istream::pos_type pos = m_is->tellg();
    d->size.emplace(pos < 0 ? 0 : (unsigned long)pos);
    return d->size.value();
}

void DataFilePrivate::saveAs(const string& path) const
{
    ofstream ofs(File::encodeName(path), ofstream::binary);
    saveAs(ofs);
}

void DataFilePrivate::saveAs(ostream &os) const
{
    m_is->clear();
    m_is->seekg(0);
    os << m_is->rdbuf();
}
