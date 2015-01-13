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
  #ifdef digidocpp_EXPORTS
    #define EXP_DIGIDOC __declspec(dllexport)
  #else
    #define EXP_DIGIDOC __declspec(dllimport)
  #endif
  #define DEPRECATED_DIGIDOCPP __declspec(deprecated)
  #pragma warning( disable: 4251 ) // shut up std::vector warnings
#else
  #if __GNUC__ >= 4
    #define EXP_DIGIDOC __attribute__ ((visibility("default")))
    #define DEPRECATED_DIGIDOCPP __attribute__ ((__deprecated__))
  #else
    #define EXP_DIGIDOC
    #define DEPRECATED_DIGIDOCPP
  #endif
#endif

#define DISABLE_COPY(Class) \
    Class(const Class &); \
    Class &operator=(const Class &)
