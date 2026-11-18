// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include <algorithm>

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

inline auto to_lower(std::string str)
{
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
    return str;
}

inline constexpr std::string_view asciiWhitespace {" \n\r\f\t\v"};

[[nodiscard]]
constexpr auto trim_prefix(std::string_view src)
{
    return src.substr(std::min<size_t>(src.find_first_not_of(asciiWhitespace), src.size()));
}

[[nodiscard]]
constexpr auto trim(std::string_view src)
{
    src = trim_prefix(src);
    return src.empty() ? src : src.substr(0, src.find_last_not_of(asciiWhitespace) + 1);
}

}
