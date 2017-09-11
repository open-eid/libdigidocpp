cmake_minimum_required(VERSION 3.0)
project(libdigidocpp VERSION 3.13.2)
if(POLICY CMP0063)
    cmake_policy(SET CMP0063 NEW)
endif()

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

include(VersionInfo)
include(GNUInstallDirs)

set_env( TSL_URL "https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml" CACHE STRING "TSL trust list primary URL" )
set_env( TSL_CERT1 "${CMAKE_SOURCE_DIR}/etc/tl-mp1.crt" CACHE FILEPATH "TSL trust list signing certificate" )
set_env( TSL_CERT2 "${CMAKE_SOURCE_DIR}/etc/tl-mp2.crt" CACHE FILEPATH "TSL trust list signing certificate" )
set_env( TSL_CERT3 "${CMAKE_SOURCE_DIR}/etc/tl-mp3.crt" CACHE FILEPATH "TSL trust list signing certificate" )
set_env( TSL_CERT4 "${CMAKE_SOURCE_DIR}/etc/tl-mp4.crt" CACHE FILEPATH "TSL trust list signing certificate" )
set_env( TSA_URL "http://tsa.sk.ee" CACHE STRING "Default TSA URL" )
set_env( SIVA_URL "https://siva.eesti.ee/validate" CACHE STRING "Default SiVa validation service URL" )
set( LIBDIGIDOC_LINKED YES CACHE BOOL "Link with libdigidoc or load runtime with dlopen" )
set( BUILD_TOOLS YES CACHE BOOL "Build digidoc-tool" )
set( BUILD_TYPE SHARED CACHE STRING "Build library as SHARED/STATIC" )
set( SIGNCERT "" CACHE STRING "Common name of certificate to used sign binaries, empty skip signing" )
set( INSTCERT "" CACHE STRING "Common name of certificate to used sign packages, empty skip signing" )
if( APPLE )
    set( FRAMEWORK YES CACHE BOOL "Build library as Mac OS X Framework" )
    set( USE_KEYCHAIN YES CACHE BOOL "Use keychain to store PKCS12 access certificate" )
endif()

find_package(Doxygen)
find_package(LibDigiDoc)
find_package(OpenSSL 1.0.1 REQUIRED)
find_package(PKCS11)
find_package(Threads)
find_package(XercesC REQUIRED)
find_package(XmlSecurityC REQUIRED)
find_package(XSD 4.0 REQUIRED)
find_package(ZLIB REQUIRED)
find_package(MiniZip QUIET)
find_package(SWIG)

if( DOXYGEN_FOUND )
    configure_file( ${CMAKE_SOURCE_DIR}/etc/Doxyfile.in Doxyfile @ONLY )
    add_custom_target( docs ALL
        ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen" VERBATIM
    )
    install( DIRECTORY ${CMAKE_BINARY_DIR}/doc/ DESTINATION ${CMAKE_INSTALL_DOCDIR} )
    install( DIRECTORY doc/ DESTINATION ${CMAKE_INSTALL_DOCDIR} )
endif()

if( WIN32 )
    add_definitions( -DUNICODE -D_CRT_SECURE_NO_WARNINGS -D_SCL_SECURE_NO_WARNINGS -DWIN32_LEAN_AND_MEAN )
endif()

enable_testing()
add_subdirectory(src)
add_subdirectory(test)
add_subdirectory(examples)
