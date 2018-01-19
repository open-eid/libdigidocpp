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

#include "../log.h"
#include "../util/File.h"

#include <minizip/zip.h>
#include <minizip/unzip.h>
#ifdef _WIN32
#include <minizip/iowin32.h>
#endif

#include <iostream>

using namespace digidoc;
using namespace std;

namespace digidoc
{
class ZipSerializePrivate
{
public:
    zlib_filefunc_def pzlib_filefunc;
    string path;
    zipFile create = nullptr;
    unzFile open = nullptr;
};
}



/**
 * Initializes ZIP file serializer.
 *
 * @param path
 */
ZipSerialize::ZipSerialize(const string& path, bool create)
 : d(new ZipSerializePrivate)
{
#ifdef _WIN32
    fill_win32_filefunc(&d->pzlib_filefunc);
#else
    fill_fopen_filefunc(&d->pzlib_filefunc);
#endif
    d->path = path;
    if(create)
    {
        DEBUG("ZipSerialize::create(%s)", path.c_str());
        d->create = zipOpen2((char*)util::File::encodeName(d->path).c_str(), APPEND_STATUS_CREATE, nullptr, &d->pzlib_filefunc);
        if(!d->create)
            THROW("Failed to create ZIP file '%s'.", d->path.c_str());
    }
    else
    {
        DEBUG("ZipSerialize::open(%s)", path.c_str());
        d->open = unzOpen2((char*)util::File::encodeName(d->path).c_str(), &d->pzlib_filefunc);
        if(!d->open)
            THROW("Failed to open ZIP file '%s'.", d->path.c_str());
    }
}

/**
 * Desctructs ZIP file serializer.
 *
 * @param path
 */
ZipSerialize::~ZipSerialize()
{
    if(d->create) zipClose(d->create, nullptr);
    if(d->open) unzClose(d->open);
    delete d;
}

/**
 * Extracts all files from ZIP file to a temporary directory on disk.
 *
 * @return returns path, where files from ZIP file were extracted.
 * @throws IOException throws exception if there were errors during
 *         extracting files to disk.
 */
vector<string> ZipSerialize::list() const
{
    if(!d->open)
        THROW("Zip file is not open");

    int unzResult = unzGoToFirstFile(d->open);
    vector<string> list;
    do
    {
        if(unzResult != UNZ_OK)
            THROW("Failed to go to the next file inside ZIP container. ZLib error: %d", unzResult);

        unz_file_info fileInfo;
        unzResult = unzGetCurrentFileInfo(d->open, &fileInfo, nullptr, 0, nullptr, 0, nullptr, 0);
        if(unzResult != UNZ_OK)
            THROW("Failed to get filename of the current file inside ZIP container. ZLib error: %d", unzResult);

        string fileName(fileInfo.size_filename, 0);
        unzResult = unzGetCurrentFileInfo(d->open, &fileInfo, &fileName[0], uLong(fileName.size()), nullptr, 0, nullptr, 0);
        if(unzResult != UNZ_OK)
            THROW("Failed to get filename of the current file inside ZIP container. ZLib error: %d", unzResult);

        list.push_back(fileName);
    } while((unzResult = unzGoToNextFile(d->open)) != UNZ_END_OF_LIST_OF_FILE);

    return list;
}

/**
 * Extracts current file from ZIP file to directory pointed in <code>directory</code> parameter.
 *
 * @param zipFile pointer to opened ZIP file.
 * @param directory directory where current file from ZIP should be extracted.
 * @throws IOException throws exception if the extraction of the current file fails from ZIP
 *         file or creating new file to disk failed.
 */
void ZipSerialize::extract(const string &file, ostream &os) const
{
    DEBUG("ZipSerializePrivate::extract(%s)", file.c_str());
    if(file[file.size()-1] == '/')
        return;

    int unzResult = unzLocateFile(d->open, file.c_str(), 1);
    if(unzResult != UNZ_OK)
        THROW("Failed to open file inside ZIP container. ZLib error: %d", unzResult);

    unzResult = unzOpenCurrentFile(d->open);
    if(unzResult != UNZ_OK)
        THROW("Failed to open file inside ZIP container. ZLib error: %d", unzResult);

    double currentStreamSize = 0;
    char buf[10240];
    for( ;; )
    {
        unzResult = unzReadCurrentFile(d->open, buf, 10240);
        if(unzResult == UNZ_EOF)
            break;
        if(unzResult <= UNZ_EOF)
        {
            unzCloseCurrentFile(d->open);
            THROW("Failed to read bytes from current file inside ZIP container. ZLib error: %d", unzResult);
        }
        currentStreamSize += unzResult;

        os.write(buf, unzResult);
        if(os.fail())
        {
            unzCloseCurrentFile(d->open);
            THROW("Failed to write file '%s' data to stream. Stream size: %f", file.c_str(), currentStreamSize);
        }
    }

    unzResult = unzCloseCurrentFile(d->open);
    if(unzResult != UNZ_OK)
        THROW("Failed to close current file inside ZIP container. ZLib error: %d", unzResult);
}

/**
 * Add new file to ZIP container. The file is actually archived to ZIP container after <code>save()</code>
 * method is called.
 *
 * @param containerPath file path inside ZIP file.
 * @param path full path of the file that should be added to ZIP file.
 * @see create()
 * @see save()
 */
void ZipSerialize::addFile(const string& containerPath, istream &is, const Properties &prop, unsigned int flags)
{
    if(!d->create)
        THROW("Zip file is not open");

    DEBUG("ZipSerialize::addFile(%s)", containerPath.c_str());
    zip_fileinfo info = {
        { uInt(prop.time.tm_sec), uInt(prop.time.tm_min), uInt(prop.time.tm_hour),
          uInt(prop.time.tm_mday), uInt(prop.time.tm_mon), uInt(prop.time.tm_year) },
        0, 0, 0 };

    // Create new file inside ZIP container.
    // 2048 general purpose bit 11 for unicode
    int compression = flags & DontCompress ? Z_NULL : Z_DEFLATED;
    int level = flags & DontCompress ? Z_NO_COMPRESSION : Z_DEFAULT_COMPRESSION;
    int zipResult = zipOpenNewFileInZip4(d->create, containerPath.c_str(),
        &info, nullptr, 0, nullptr, 0, prop.comment.c_str(), compression, level, 0,
        -MAX_WBITS, DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY, nullptr, 0, 0, 2048);
    if(zipResult != ZIP_OK)
        THROW("Failed to create new file inside ZIP container. ZLib error: %d", zipResult);

    is.clear();
    is.seekg(0);
    char buf[10240];
    while( is )
    {
        is.read(buf, 10240);
        if(is.gcount() <= 0)
            break;

        zipResult = zipWriteInFileInZip(d->create, buf, unsigned(is.gcount()));
        if(zipResult != ZIP_OK)
        {
            zipCloseFileInZip(d->create);
            THROW("Failed to write bytes to current file inside ZIP container. ZLib error: %d", zipResult);
        }
    }

    zipResult = zipCloseFileInZip(d->create);
    if(zipResult != ZIP_OK)
        THROW("Failed to close current file inside ZIP container. ZLib error: %d", zipResult);
}

ZipSerialize::Properties ZipSerialize::properties(const string &file) const
{
    int unzResult = unzLocateFile(d->open, file.c_str(), 0);
    if(unzResult != UNZ_OK)
        THROW("Failed to open file inside ZIP container. ZLib error: %d", unzResult);

    unz_file_info info;
    unzResult = unzGetCurrentFileInfo(d->open, &info, nullptr, 0, nullptr, 0, nullptr, 0);
    if(unzResult != UNZ_OK)
        THROW("Failed to get filename of the current file inside ZIP container. ZLib error: %d", unzResult);

    tm time = { int(info.tmu_date.tm_sec), int(info.tmu_date.tm_min), int(info.tmu_date.tm_hour),
            int(info.tmu_date.tm_mday), int(info.tmu_date.tm_mon), int(info.tmu_date.tm_year), 0, 0, 0
#ifndef _WIN32
             , 0, 0
#endif
    };
    ZipSerialize::Properties prop;
    prop.time = time;
    prop.size = info.uncompressed_size;

    if(info.size_file_comment == 0)
        return prop;

    prop.comment.resize(info.size_file_comment);
    unzResult = unzGetCurrentFileInfo(d->open, &info, nullptr, 0, nullptr, 0, &prop.comment[0], uLong(prop.comment.size()));
    if(unzResult != UNZ_OK)
        THROW("Failed to get filename of the current file inside ZIP container. ZLib error: %d", unzResult);

    return prop;
}

/**
 * Creates new ZIP file and adds all the added files to the ZIP file.
 *
 * @throws IOException throws exception if the file to be added did not exists or creating new
 *         ZIP file failed.
 * @see create()
 * @see addFile(const string& containerPath, const string& path)
 */
void ZipSerialize::save()
{
    DEBUG("ZipSerialize::close()");
    int zipResult = zipClose(d->create, nullptr);
    d->create = 0;
    if(zipResult != ZIP_OK)
        THROW("Failed to close ZIP file. ZLib error: %d", zipResult);
}
