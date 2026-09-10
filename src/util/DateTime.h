// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include <ctime>
#include <string>

namespace digidoc
{
    namespace util
    {
        class date
        {
        public:
            static struct tm gmtime(time_t t);
            static bool is_empty(const tm &t);
            static time_t mkgmtime(tm &t);
            static std::string to_string(time_t t);
            static std::string to_string(const tm &date);
        };
    }
}
