cmake_minimum_required(VERSION 2.8)
project(libdigidocpp)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")
set(CMAKE_FIND_ROOT_PATH ${CMAKE_OSX_SYSROOT})

if( "$ENV{TSL_URL}" STREQUAL "" )
	set( TSL_URL "https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml" CACHE STRING "TSL trust list primary url" )
else()
	set( TSL_URL $ENV{TSL_URL} CACHE STRING "TSL trust list primary url" )
endif()
if( "$ENV{TSL_CERT}" STREQUAL "" )
	set( TSL_CERT ${CMAKE_SOURCE_DIR}/etc/tl-mp.crt CACHE FILEPATH "TSL trust list signing cert" )
else()
	set( TSL_CERT $ENV{TSL_CERT} CACHE FILEPATH "TSL trust list signing cert" )
endif()
set( LIBDIGIDOC_LINKED true CACHE BOOL "Link with libdigidoc" )
set( INSTALL_DOC false CACHE BOOL "Install documentation" )
set( TSA_URL $ENV{TSA_URL} CACHE STRING "Default TSA url" )
if( APPLE )
    set( FRAMEWORK true CACHE BOOL "Build library as Mac OS X Framework" )
    set( USE_KEYCHAIN true CACHE BOOL "Use keychain to store pkcs12 access cert" )
endif()

include(VersionInfo)
include(GNUInstallDirs)

find_package(Doxygen)
find_package(LibDigiDoc)
find_package(OpenSSL REQUIRED)
find_package(PKCS11)
find_package(XercesC REQUIRED)
find_package(XmlSecurityC REQUIRED)
find_package(XSD REQUIRED)
find_package(ZLIB REQUIRED)
find_package(MiniZip QUIET)
find_package(SWIG)

if( INSTALL_DOC )
    if( DOXYGEN_FOUND )
        configure_file( ${CMAKE_SOURCE_DIR}/etc/Doxyfile.in Doxyfile @ONLY )
        add_custom_target( docs ALL
            ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating API documentation with Doxygen" VERBATIM
        )
        install( DIRECTORY ${CMAKE_BINARY_DIR}/doc/ DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/libdigidocpp )
    endif()
    install( DIRECTORY doc/ DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/libdigidocpp PATTERN ".svn" EXCLUDE )
endif()

if( WIN32 )
    add_definitions( -DUNICODE -D_CRT_SECURE_NO_WARNINGS -D_SCL_SECURE_NO_WARNINGS )
endif()

add_subdirectory(src)
add_subdirectory(test)
