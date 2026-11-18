// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include <algorithm>
#include <cctype>
#include <charconv>
#include <string>
#include <string_view>
#include <utility>

namespace digidoc
{

template<typename C, typename P>
[[nodiscard]]
constexpr bool all_of(const C &list, P pred)
{
    return std::all_of(list.begin(), list.end(), std::forward<P>(pred));
}

template<typename C, typename P>
[[nodiscard]]
constexpr bool any_of(const C &list, P pred)
{
    return std::any_of(list.begin(), list.end(), std::forward<P>(pred));
}

template<typename C, typename T>
[[nodiscard]]
constexpr bool contains(const C &list, T value)
{
    return std::find(list.begin(), list.end(), std::forward<T>(value)) != list.end();
}

template<typename C, typename P>
[[nodiscard]]
constexpr bool none_of(const C &list, P pred)
{
    return std::none_of(list.begin(), list.end(), std::forward<P>(pred));
}

template<typename T>
[[nodiscard]]
constexpr bool starts_with(T str, std::string_view needle) {
    return str.size() >= needle.size() && str.compare(0, needle.size(), needle) == 0;
}

inline auto to_lower(std::string str)
{
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
    return str;
}

template<typename T>
[[nodiscard]]
constexpr bool parseInteger(std::string_view text, T &value, int base)
{
    if(text.empty())
        return false;
    const auto *end = text.data() + text.size();
    const auto [ptr, ec] = std::from_chars(text.data(), end, value, base);
    return ec == std::errc{} && ptr == end;
}

[[nodiscard]]
constexpr auto trim_prefix(std::string_view src, std::string_view chars = " \n\r\f\t\v")
{
    return src.substr(std::min(src.find_first_not_of(chars), src.size()));
}

[[nodiscard]]
constexpr auto trim_suffix(std::string_view src, std::string_view chars)
{
    const auto end = src.find_last_not_of(chars);
    return src.substr(0, end == std::string_view::npos ? 0 : end + 1);
}

[[nodiscard]]
constexpr auto trim(std::string_view src, std::string_view chars)
{
    return trim_suffix(trim_prefix(src, chars), chars);
}

}
