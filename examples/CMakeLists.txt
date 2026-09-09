# SPDX-FileCopyrightText: Estonian Information System Authority
# SPDX-License-Identifier: LGPL-2.1-or-later

add_executable( pkcs11sign pkcs11sign.cpp )
set_target_properties( pkcs11sign PROPERTIES
	LINK_LIBRARIES digidocpp
	EXCLUDE_FROM_ALL yes
)
