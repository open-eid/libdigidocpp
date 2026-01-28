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

#pragma once

#include "DataFile.h"

#include <istream>
#include <memory>
#include <optional>

namespace digidoc
{

constexpr unsigned long MAX_MEM_FILE = 500UL*1024UL*1024UL;

class Digest;
class ZipSerialize;

class DataFilePrivate final: public DataFile
{
public:
    DataFilePrivate(std::unique_ptr<std::istream> &&is, std::string filename, std::string mediatype, std::string id = {});
    DataFilePrivate(const ZipSerialize &z, std::string filename, std::string mediatype);
    ~DataFilePrivate() noexcept final;

    std::string id() const final { return m_id.empty() ? m_filename : m_id; }
    std::string fileName() const final { return m_filename; }
    unsigned long fileSize() const final;
    std::string mediaType() const final { return m_mediatype; }

    void digest(const Digest &method) const;
    std::vector<unsigned char> calcDigest(const std::string &method) const final;
    void saveAs(std::ostream &os) const final;
    void saveAs(const std::string& path) const final;

    struct Private;
    std::unique_ptr<Private> d;
    std::unique_ptr<std::istream> m_is;
    std::string m_id, m_filename, m_mediatype;
};
}
