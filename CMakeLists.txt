cmake_minimum_required(VERSION 3.10)
project(libdigidocpp VERSION 3.15.0)
if(POLICY CMP0074)
    cmake_policy(SET CMP0074 NEW)
endif()
if(POLICY CMP0078)
    cmake_policy(SET CMP0078 NEW)
endif()
if(POLICY CMP0086)
    cmake_policy(SET CMP0086 NEW)
endif()
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)

include(VersionInfo)
include(GNUInstallDirs)

set_env( TSL_URL "https://ec.europa.eu/tools/lotl/eu-lotl.xml" CACHE STRING "TSL trust list primary URL" )
set_env( TSL_CERTS
    ${CMAKE_SOURCE_DIR}/etc/tl-mp1.crt
    ${CMAKE_SOURCE_DIR}/etc/tl-mp2.crt
    ${CMAKE_SOURCE_DIR}/etc/tl-mp3.crt
    ${CMAKE_SOURCE_DIR}/etc/tl-mp4.crt
    ${CMAKE_SOURCE_DIR}/etc/tl-mp5.crt
    ${CMAKE_SOURCE_DIR}/etc/tl-mp6.crt
    CACHE FILEPATH "TSL trust list signing certificates" )
set_env( TSA_URL "http://dd-at.ria.ee/tsa" CACHE STRING "Default TSA URL" )
set_env( SIVA_URL "https://siva.eesti.ee/V3/validate" CACHE STRING "Default SiVa validation service URL" )
set( BUILD_TOOLS YES CACHE BOOL "Build digidoc-tool" )
set( BUILD_SHARED_LIBS YES CACHE BOOL "Build library as SHARED or STATIC" )
set( SIGNCERT "" CACHE STRING "Common name of certificate to used sign binaries, empty skip signing" )
set( CROSSSIGNCERT "" CACHE STRING "Common name of certificate to used cross sign binaries, empty skip signing" )
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
if( APPLE )
    set( FRAMEWORK YES CACHE BOOL "Build library as Mac OS X Framework" )
    set( USE_KEYCHAIN YES CACHE BOOL "Use keychain to store PKCS12 access certificate" )
endif()

find_package(Doxygen)
find_package(OpenSSL 1.1.1 REQUIRED)
find_package(PKCS11)
#find_package(PoDoFo)
find_package(Threads)
find_package(XmlSecurityC REQUIRED)
find_package(XSD 4.0 REQUIRED)
find_package(ZLIB REQUIRED)
find_package(MiniZip 1 QUIET) # version range (0...<2.0.0) requires CMake>=3.19
if(UNIX AND NOT APPLE)
    find_package(PkgConfig)
    pkg_check_modules(MINIZIP minizip IMPORTED_TARGET minizip<2.0.0)
endif()
find_package(SWIG)
find_package(JNI)
find_package(Python3 COMPONENTS Interpreter Development)

if(Python3_FOUND)
    add_library(PythonModule INTERFACE)
    target_link_libraries(PythonModule INTERFACE Python3::Module)
else()
    find_package(PythonLibs)
    if(PYTHONLIBS_FOUND)
        add_library(PythonModule INTERFACE)
        target_include_directories(PythonModule INTERFACE ${PYTHON_INCLUDE_DIRS})
        target_link_libraries(PythonModule INTERFACE ${PYTHON_LIBRARIES})
    endif()
endif()

if( DOXYGEN_FOUND )
    configure_file( ${CMAKE_SOURCE_DIR}/etc/Doxyfile.in Doxyfile @ONLY )
    add_custom_target( docs ALL
        Doxygen::doxygen Doxyfile
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
