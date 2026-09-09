// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "DataFile.h"

#include <filesystem>
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
    std::filesystem::path m_tempFile;
    std::unique_ptr<std::istream> m_is;
    std::string m_id, m_filename, m_mediatype;
};
}
