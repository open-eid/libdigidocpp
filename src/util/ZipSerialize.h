// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "Exports.h"
#include "log.h"

#include <memory>
#include <string>
#include <vector>

namespace digidoc
{
/**
 * Saves files to ZIP file and extracts the ZIP file on demand. Uses ZLib to implement ZIP file operations.
 */
class ZipSerialize
{
public:
    struct Read {
        static constexpr size_t maxSize = 10UL*1024*1024;
        size_t operator ()(void *data, size_t size) const;
        template<class T = std::string>
        T operator ()(size_t maxAlloc = maxSize) const
        {
            if(size > maxAlloc)
                THROW("ZIP entry uncompressed size %zu exceeds limit", size);
            T t(size, 0);
            t.resize(operator ()(t.data(), t.size()));
            char extra{};
            if(operator ()(&extra, 1) > 0)
                THROW("ZIP entry actual size exceeds uncompressed_size %zu", size);
            return t;
        }
        template<class T>
        constexpr operator T() const { return operator()<T>(); }
        std::unique_ptr<void, int (*)(void*)> d;
        size_t size;
    };
    struct Write {
        void operator ()(const void *data, size_t size) const;
        template<class T>
        constexpr void operator ()(const T &data) const
        {
            operator ()(data.data(), data.size());
        }
        std::unique_ptr<void, int (*)(void*)> d;
    };

    struct Properties {
        std::string comment;
        time_t time;
        unsigned long size;
    };

    ZipSerialize(const std::string &path, bool create);

    std::vector<std::string> list() const;
    Write addFile(std::string_view containerPath, const Properties &prop, bool compress = true) const;
    std::string mimetype() const;
    Read read(std::string_view file) const;
    Properties properties(const std::string &file) const;

private:
    std::unique_ptr<void, int(*)(void*)> d;
};
}
