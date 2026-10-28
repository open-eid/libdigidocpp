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
  #ifdef digidocpp_STATIC
    #define DIGIDOCPP_EXPORT
  #elifdef digidocpp_EXPORTS
    #define DIGIDOCPP_EXPORT __declspec(dllexport)
  #else
    #define DIGIDOCPP_EXPORT __declspec(dllimport)
  #endif
  #if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
    #define DIGIDOCPP_DEPRECATED __declspec(deprecated)
  #else
    #define DIGIDOCPP_DEPRECATED
  #endif
  #pragma warning( disable: 4251 ) // shut up std::vector warnings
#else
  #define DIGIDOCPP_EXPORT __attribute__ ((visibility("default")))
  #define DIGIDOCPP_DEPRECATED __attribute__ ((__deprecated__))
#endif

#define DISABLE_COPY(Class) \
    Class(const Class &) = delete; \
    Class &operator=(const Class &) = delete; \
    Class(Class &&) noexcept = delete; \
    Class &operator=(Class &&) noexcept = delete
