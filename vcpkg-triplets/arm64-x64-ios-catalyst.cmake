# SPDX-FileCopyrightText: Estonian Information System Authority
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Based on vcpkg's arm64-ios community triplet (MIT), https://github.com/microsoft/vcpkg
# Extended for Mac Catalyst: macosx sysroot, universal binary, 16.0 deployment target.

set(VCPKG_TARGET_ARCHITECTURE arm64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_CMAKE_SYSTEM_NAME iOS)
set(VCPKG_OSX_SYSROOT macosx)
set(VCPKG_OSX_ARCHITECTURES arm64 x86_64)
set(VCPKG_OSX_DEPLOYMENT_TARGET 16.0)
