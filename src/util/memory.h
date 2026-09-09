// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

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
        D(p);
    }
};

template<typename> struct free_argument;
template<class T, class R>
struct free_argument<R (*)(T *)>
{
    using type = T;
};
template<class T, class R>
struct free_argument<R (&)(T *)>
{
    using type = T;
};

template <auto D>
using free_argument_t = typename free_argument<decltype(D)>::type;
template <class T>
using unique_free_t = std::unique_ptr<T, void(*)(T*)>;
template <auto D>
using unique_free_d = std::unique_ptr<free_argument_t<D>,free_deleter<D>>;

template<class T, class U>
[[nodiscard]]
constexpr unique_free_t<T> make_unique_ptr(U *p, void (*d)(T*)) noexcept
{
    return {static_cast<T*>(p), d};
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

template<auto D>
[[nodiscard]]
constexpr auto make_unique_ptr(nullptr_t) noexcept
{
    return unique_free_d<D>(nullptr);
}

template<auto D>
[[nodiscard]]
constexpr auto make_unique_cast(void *p) noexcept
{
    using T = free_argument_t<D>;
    return make_unique_ptr<D>(static_cast<T*>(p));
}

}
