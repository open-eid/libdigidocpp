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

#ifdef WIN32
  #include <winapifamily.h>
  #ifdef digidocpp_EXPORTS
    #define DIGIDOCPP_EXPORT __declspec(dllexport)
  #else
    #define DIGIDOCPP_EXPORT __declspec(dllimport)
  #endif
  #if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
    #define DIGIDOCPP_DEPRECATED __declspec(deprecated)
  #else
    #define DIGIDOCPP_DEPRECATED
  #endif
  #if _MSC_VER >= 1900
    #define DIGIDOCPP_NOEXCEPT noexcept
  #else
    #define DIGIDOCPP_NOEXCEPT
  #endif
  #define DIGIDOCPP_WARNING_PUSH __pragma(warning(push))
  #define DIGIDOCPP_WARNING_POP __pragma(warning(pop))
  #define DIGIDOCPP_WARNING_DISABLE_CLANG(text)
  #define DIGIDOCPP_WARNING_DISABLE_GCC(text)
  #define DIGIDOCPP_WARNING_DISABLE_MSVC(number) __pragma(warning(disable: number))
  #pragma warning( disable: 4251 ) // shut up std::vector warnings
#else
  #define DIGIDOCPP_EXPORT __attribute__ ((visibility("default")))
  #define DIGIDOCPP_DEPRECATED __attribute__ ((__deprecated__))
  #define DIGIDOCPP_NOEXCEPT noexcept
  #define DIGIDOCPP_DO_PRAGMA(text) _Pragma(#text)
  #define DIGIDOCPP_WARNING_PUSH DIGIDOCPP_DO_PRAGMA(GCC diagnostic push)
  #define DIGIDOCPP_WARNING_POP DIGIDOCPP_DO_PRAGMA(GCC diagnostic pop)
  #if __clang__
  #define DIGIDOCPP_WARNING_DISABLE_CLANG(text) DIGIDOCPP_DO_PRAGMA(clang diagnostic ignored text)
  #else
  #define DIGIDOCPP_WARNING_DISABLE_CLANG(text)
  #endif
  #define DIGIDOCPP_WARNING_DISABLE_GCC(text) DIGIDOCPP_DO_PRAGMA(GCC diagnostic ignored text)
  #define DIGIDOCPP_WARNING_DISABLE_MSVC(text)
#endif

#define DISABLE_COPY(Class) \
    Class(const Class &) = delete; \
    Class &operator=(const Class &) = delete
