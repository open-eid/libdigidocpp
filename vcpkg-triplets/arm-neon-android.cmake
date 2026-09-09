# SPDX-FileCopyrightText: Estonian Information System Authority
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Based on vcpkg's triplet of the same name (MIT), https://github.com/microsoft/vcpkg
# Differs only in static CRT linkage and Android API level 30.

set(VCPKG_TARGET_ARCHITECTURE arm)
set(VCPKG_CRT_LINKAGE static)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_CMAKE_SYSTEM_NAME Android)
set(VCPKG_CMAKE_SYSTEM_VERSION 30)
set(VCPKG_MAKE_BUILD_TRIPLET "--host=armv7a-linux-androideabi")
set(VCPKG_CMAKE_CONFIGURE_OPTIONS -DANDROID_ABI=armeabi-v7a -DANDROID_ARM_NEON=ON)
