include_directories( ${CMAKE_SOURCE_DIR}/src )
add_executable( pkcs11sign
	pkcs11sign.cpp
	../src/crypto/PKCS11Signer.cpp
	../src/log.cpp
	../src/util/File.cpp
)
set_target_properties( pkcs11sign PROPERTIES
	LINK_LIBRARIES digidocpp
	EXCLUDE_FROM_ALL yes
)
