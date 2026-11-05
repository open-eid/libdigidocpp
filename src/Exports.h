// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: LGPL-2.1-or-later

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
