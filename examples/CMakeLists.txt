add_executable( pkcs11sign pkcs11sign.cpp )
set_target_properties( pkcs11sign PROPERTIES
	LINK_LIBRARIES digidocpp
	EXCLUDE_FROM_ALL yes
)
