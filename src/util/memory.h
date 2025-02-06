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

#include <memory>

namespace digidoc
{

template<auto D>
struct free_deleter
{
    template<class T>
    void operator()(T *p) const noexcept
    {
        if (p) D(p);
    }
};

template <class T>
using unique_free_t = std::unique_ptr<T, void(*)(T*)>;

template<class T, class U>
[[nodiscard]]
constexpr unique_free_t<T> make_unique_ptr(U *p, void (*d)(T*)) noexcept
{
    return {static_cast<T*>(p), d};
}

template<class T>
[[nodiscard]]
constexpr unique_free_t<T> make_unique_ptr(nullptr_t, void (*d)(T*)) noexcept
{
    return {nullptr, d};
}

template<class T, typename D>
[[nodiscard]]
constexpr std::unique_ptr<T, D> make_unique_ptr(T *p, D d) noexcept
{
    return {p, std::forward<D>(d)};
}

template<auto D, class T>
[[nodiscard]]
constexpr auto make_unique_ptr(T *p) noexcept
{
    return std::unique_ptr<T, free_deleter<D>>(p);
}

}
