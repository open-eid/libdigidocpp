# SPDX-FileCopyrightText: Estonian Information System Authority
# SPDX-License-Identifier: LGPL-2.1-or-later

prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=@CMAKE_INSTALL_FULL_BINDIR@
libdir=@CMAKE_INSTALL_FULL_LIBDIR@
includedir=@CMAKE_INSTALL_FULL_INCLUDEDIR@

Name: libdigidocpp
Description: Libdigidocpp C++ library for handling digitally signed documents
Version: @PROJECT_VERSION@
Libs: -L${libdir} -ldigidocpp
Cflags: -I${includedir}
