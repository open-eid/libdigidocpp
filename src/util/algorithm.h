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

template<typename T>
[[nodiscard]]
constexpr bool starts_with(T str, T needle) {
    return str.size() >= needle.size() && str.compare(0, needle.size(), needle) == 0;
}

}
