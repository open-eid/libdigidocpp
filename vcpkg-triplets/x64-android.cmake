# SPDX-FileCopyrightText: Estonian Information System Authority
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Based on vcpkg's triplet of the same name (MIT), https://github.com/microsoft/vcpkg
# Differs only in static CRT linkage and Android API level 30.

set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE static)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_CMAKE_SYSTEM_NAME Android)
set(VCPKG_CMAKE_SYSTEM_VERSION 30)
set(VCPKG_MAKE_BUILD_TRIPLET "--host=x86_64-linux-android")
set(VCPKG_CMAKE_CONFIGURE_OPTIONS -DANDROID_ABI=x86_64)
