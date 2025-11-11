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

#include "ZipSerialize.h"

#include "Container.h"
#include "DateTime.h"
#include "log.h"
#include "File.h"

#include <zlib.h>
#include <minizip/unzip.h>
#include <minizip/zip.h>
#ifdef _WIN32
#include <minizip/iowin32.h>
#endif

#include <algorithm>

using namespace digidoc;
using namespace std;

/**
 * Initializes ZIP file serializer.
 *
 * @param path
 */
ZipSerialize::ZipSerialize(const string &path, bool create)
    : d{nullptr, create ? [](void *handle) { return zipClose(handle, appInfo().c_str()); } : &unzClose}
{
    zlib_filefunc_def def {};
#ifdef _WIN32
    fill_win32_filefunc(&def);
#else
    fill_fopen_filefunc(&def);
#endif
    if(create)
    {
        DEBUG("ZipSerialize::create(%s)", path.c_str());
        d.reset(zipOpen2((const char*)util::File::encodeName(path).c_str(), APPEND_STATUS_CREATE, nullptr, &def));
        if(!d)
            THROW("Failed to create ZIP file '%s'.", path.c_str());
    }
    else
    {
        DEBUG("ZipSerialize::open(%s)", path.c_str());
        d.reset(unzOpen2((const char*)util::File::encodeName(path).c_str(), &def));
        if(!d)
            THROW("Failed to open ZIP file '%s'.", path.c_str());
    }
}

/**
 * List all files from ZIP file.
 *
 * @return returns list of ZIP content.
 * @throws Exception throws exception if there were errors during locating files in zip.
 */
vector<string> ZipSerialize::list() const
{
    if(!d)
        THROW("Zip file is not open");

    vector<string> list;
    for(int unzResult = unzGoToFirstFile(d.get()); unzResult != UNZ_END_OF_LIST_OF_FILE; unzResult = unzGoToNextFile(d.get()))
    {
        if(unzResult != UNZ_OK)
            THROW("Failed to go to the next file inside ZIP container. ZLib error: %d", unzResult);

        unz_file_info fileInfo{};
        unzResult = unzGetCurrentFileInfo(d.get(), &fileInfo, nullptr, 0, nullptr, 0, nullptr, 0);
        if(unzResult != UNZ_OK)
            THROW("Failed to get filename of the current file inside ZIP container. ZLib error: %d", unzResult);

        auto &fileName = list.emplace_back(fileInfo.size_filename, 0);
        unzResult = unzGetCurrentFileInfo(d.get(), nullptr, fileName.data(), uLong(fileName.size()), nullptr, 0, nullptr, 0);
        if(unzResult != UNZ_OK)
            THROW("Failed to get filename of the current file inside ZIP container. ZLib error: %d", unzResult);

        if(count(list.cbegin(), list.cend(), fileName) > 1)
            THROW("Found multiple references of file '%s' in zip container.", fileName.c_str());
    }

    if(list.empty())
        THROW("Failed to parse container");

    return list;
}

/**
 * Reads current file from ZIP file.
 *
 * @param file path to opened ZIP in file.
 * @throws Exception throws exception if the extraction of the current file fails from ZIP file
 */
ZipSerialize::Read ZipSerialize::read(string_view file) const
{
    if(!d)
        THROW("Zip file is not open");

    DEBUG("ZipSerialize::read(%.*s)", int(file.size()), file.data());
    if(file.empty() || file.back() == '/')
        return {{nullptr, unzCloseCurrentFile}, 0};

    int unzResult = unzLocateFile(d.get(), file.data(), 1);
    if(unzResult != UNZ_OK)
        THROW("Failed to locate '%.*s' inside ZIP container. ZLib error: %d", int(file.size()), file.data(), unzResult);

    unzResult = unzOpenCurrentFile(d.get());
    if(unzResult != UNZ_OK)
        THROW("Failed to open '%.*s' inside ZIP container. ZLib error: %d", int(file.size()), file.data(), unzResult);

    unz_file_info info {};
    unzGetCurrentFileInfo(d.get(), &info, nullptr, 0, nullptr, 0, nullptr, 0);

    return {{d.get(), unzCloseCurrentFile}, size_t(info.uncompressed_size)};
}

/**
 * Add new file to ZIP container.
 *
 * @param containerPath file path inside ZIP file.
 * @param prop Properties added for file in ZIP file.
 * @param compress File should be compressed in ZIP file.
 * @return Write struct for data input
 * @throws Exception throws exception if there were errors during locating files in zip.
 */
ZipSerialize::Write ZipSerialize::addFile(string_view containerPath, const Properties &prop, bool compress) const
{
    if(!d)
        THROW("Zip file is not open");

    DEBUG("ZipSerialize::addFile(%.*s)", int(containerPath.size()), containerPath.data());
    tm time = util::date::gmtime(prop.time);
    zip_fileinfo info {
        { time.tm_sec, time.tm_min, time.tm_hour,
          time.tm_mday, time.tm_mon, time.tm_year },
        0, 0, 0 };

    // Create new file inside ZIP container.
    int method = compress ? Z_DEFLATED : Z_NULL;
    int level = compress ? Z_DEFAULT_COMPRESSION : Z_NO_COMPRESSION;
    static constexpr uLong UTF8_encoding = 1 << 11; // general purpose bit 11 for unicode
    int zipResult = zipOpenNewFileInZip4(d.get(), containerPath.data(),
        &info, nullptr, 0, nullptr, 0, prop.comment.c_str(), method, level, 0,
        -MAX_WBITS, DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY, nullptr, 0, 0, UTF8_encoding);
    if(zipResult != ZIP_OK)
        THROW("Failed to create new file inside ZIP container. ZLib error: %d", zipResult);

    return {{d.get(), zipCloseFileInZip}};
}

/**
 * Reads mimetype.
 *
 * @throws IOException exception is thrown if there was error reading mimetype file.
 */
string ZipSerialize::mimetype() const
{
    DEBUG("ZipSerialize::mimetype()");
    string text = read("mimetype");
    text.erase(text.find_last_not_of(" \n\r\f\t\v") + 1);
    if(text.empty())
        THROW("Failed to read mimetype.");
    // Contains UTF-16 BOM
    if(text.find("\xFF\xEF") == 0 || text.find("\xEF\xFF") == 0)
        THROW("Mimetype file must be UTF-8 format.");
    // contains UTF-8 BOM, remove
    if(text.find("\xEF\xBB\xBF") == 0)
        text.erase(text.cbegin(), text.cbegin() + 3);
    return text;
}

ZipSerialize::Properties ZipSerialize::properties(const string &file) const
{
    int unzResult = unzLocateFile(d.get(), file.c_str(), 1);
    if(unzResult != UNZ_OK)
        THROW("Failed to locate '%s' inside ZIP container. ZLib error: %d", file.c_str(), unzResult);

    unz_file_info info;
    unzResult = unzGetCurrentFileInfo(d.get(), &info, nullptr, 0, nullptr, 0, nullptr, 0);
    if(unzResult != UNZ_OK)
        THROW("Failed to get filename of the current file inside ZIP container. ZLib error: %d", unzResult);

    tm time { info.tmu_date.tm_sec, info.tmu_date.tm_min, info.tmu_date.tm_hour,
            info.tmu_date.tm_mday, info.tmu_date.tm_mon, info.tmu_date.tm_year, 0, 0, 0,
#ifndef _WIN32
            0, nullptr
#endif
    };
    Properties prop { string(size_t(info.size_file_comment), 0), util::date::mkgmtime(time), info.uncompressed_size };
    if(prop.comment.empty())
        return prop;

    unzResult = unzGetCurrentFileInfo(d.get(), nullptr, nullptr, 0, nullptr, 0, prop.comment.data(), uLong(prop.comment.size()));
    if(unzResult != UNZ_OK)
        THROW("Failed to get filename of the current file inside ZIP container. ZLib error: %d", unzResult);

    return prop;
}

size_t ZipSerialize::Read::operator()(void *data, size_t size) const
{
    auto result = unzReadCurrentFile(d.get(), data, size);
    if(result >= UNZ_EOF)
        return size_t(result);
    THROW("Failed to read bytes from ZIP container. ZLib error: %d", result);
}

void ZipSerialize::Write::operator()(const void *data, size_t size) const
{
    if(auto result = zipWriteInFileInZip(d.get(), data, unsigned(size)); result != ZIP_OK)
        THROW("Failed to write bytes to current file inside ZIP container. ZLib error: %d", result);
}
