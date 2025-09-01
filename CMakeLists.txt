cmake_minimum_required(VERSION 3.22)
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()
if(POLICY CMP0177)
    cmake_policy(SET CMP0177 NEW)
endif()
project(libdigidocpp VERSION 4.4.0
    DESCRIPTION "C++ library for digital signatures and validation of digitally signed documents"
    HOMEPAGE_URL https://github.com/open-eid/libdigidocpp
)
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)
list(APPEND CMAKE_PREFIX_PATH ${CMAKE_INSTALL_PREFIX})

macro(SET_ENV NAME DEF)
    if(DEFINED ENV{${NAME}})
        set(${NAME} $ENV{${NAME}} ${ARGN})
    else()
        set(${NAME} ${DEF} ${ARGN})
    endif()
endmacro()

include(GNUInstallDirs)

set_env( TSL_URL "https://ec.europa.eu/tools/lotl/eu-lotl.xml" CACHE STRING "TSL trust list primary URL" )
set_env( TSL_CERTS
    ${CMAKE_SOURCE_DIR}/etc/tl-mp1.crt
    ${CMAKE_SOURCE_DIR}/etc/tl-mp2.crt
    ${CMAKE_SOURCE_DIR}/etc/tl-mp3.crt
    ${CMAKE_SOURCE_DIR}/etc/tl-mp4.crt
    ${CMAKE_SOURCE_DIR}/etc/tl-mp5.crt
    ${CMAKE_SOURCE_DIR}/etc/tl-mp6.crt
    ${CMAKE_SOURCE_DIR}/etc/tl-mp7.crt
    CACHE FILEPATH "TSL trust list signing certificates" )
set_env(TSA_URL "https://eid-dd.ria.ee/ts" CACHE STRING "Default TSA URL")
set_env( SIVA_URL "https://siva.eesti.ee/V3/validate" CACHE STRING "Default SiVa validation service URL" )
set( BUILD_TOOLS YES CACHE BOOL "Build digidoc-tool" )
set( BUILD_SHARED_LIBS YES CACHE BOOL "Build library as SHARED or STATIC" )
set( SIGNCERT "" CACHE STRING "Common name of certificate to used sign binaries, empty skip signing" )
set( CROSSSIGNCERT "" CACHE STRING "Common name of certificate to used cross sign binaries, empty skip signing" )
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN YES)
set(CMAKE_DEBUG_POSTFIX "d" CACHE STRING "Adds a postfix for debug-built libraries.")
set(CPACK_PACKAGE_VERSION ${VERSION})
set(CPACK_GENERATOR RPM)
set(CPACK_PACKAGE_CONTACT "RIA <info@ria.ee>")
set(CPACK_PACKAGE_VENDOR RIA)
set(CPACK_PACKAGING_INSTALL_PREFIX /usr)
list(APPEND CPACK_RPM_RELOCATION_PATHS ${CMAKE_INSTALL_SYSCONFDIR})
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
set(CPACK_RPM_PACKAGE_RELEASE_DIST ON)
include(CPack)
if(APPLE)
    set(FRAMEWORK YES CACHE BOOL "Build library as Mac OS X Framework")
    set(FRAMEWORK_DESTINATION /Library/Frameworks CACHE PATH "Mac OS X Framework install destination")
endif()

find_package(OpenSSL 3.0.0 REQUIRED)
find_package(PKCS11)
#find_package(PoDoFo)
find_package(Threads)
find_package(LibXml2 REQUIRED)
find_package(ZLIB REQUIRED)
find_package(MiniZip 1 QUIET)
if(UNIX)
    find_package(PkgConfig)
    find_package(unofficial-xmlsec QUIET)
    if(TARGET unofficial::xmlsec::xmlsec1-openssl)
        add_library(xmlsec ALIAS unofficial::xmlsec::xmlsec1-openssl)
    else()
        pkg_check_modules(XMLSEC1_OPENSSL xmlsec1-openssl REQUIRED IMPORTED_TARGET)
        add_library(xmlsec ALIAS PkgConfig::XMLSEC1_OPENSSL)
    endif()
    if(NOT APPLE)
        pkg_check_modules(MINIZIP minizip IMPORTED_TARGET)
    endif()
else()
    find_package(unofficial-xmlsec REQUIRED)
    add_library(xmlsec ALIAS unofficial::xmlsec::xmlsec1-openssl)
endif()
find_package(SWIG)
if(SWIG_FOUND)
    find_package(Java COMPONENTS Development)
    find_package(JNI)
    find_package(Python3 COMPONENTS Development)
    if((WIN32 OR APPLE) AND CMAKE_VERSION VERSION_GREATER_EQUAL "3.24")
        find_package(Python3 COMPONENTS Development.SABIModule)
    endif()
endif()

find_package(Doxygen)
if(TARGET Doxygen::doxygen)
    configure_file( ${CMAKE_SOURCE_DIR}/etc/Doxyfile.in Doxyfile @ONLY )
    add_custom_target( docs ALL
        Doxygen::doxygen Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen" VERBATIM
    )
    install( DIRECTORY ${CMAKE_BINARY_DIR}/doc/ DESTINATION ${CMAKE_INSTALL_DOCDIR} )
    install( DIRECTORY doc/ DESTINATION ${CMAKE_INSTALL_DOCDIR} )
endif()

enable_testing()
add_subdirectory(src)
add_subdirectory(examples)

find_package(Boost COMPONENTS unit_test_framework QUIET)
if(TARGET Boost::unit_test_framework)
    add_subdirectory(test)
endif()
