if(NOT MINIZIP_FOUND)
    message(STATUS "MiniZip not found; using bundled copy.")
    if(WIN32)
        list( APPEND MINIZIP_SRCS minizip/iowin32.c )
    endif()
    add_library( minizip STATIC minizip/zip.c minizip/unzip.c minizip/ioapi.c ${MINIZIP_SRCS} )
    if(CMAKE_COMPILER_IS_GNUCC OR __COMPILER_GNU)
        set_target_properties( minizip PROPERTIES COMPILE_FLAGS "-fPIC -Wno-unused-parameter" )
    endif()
    set( MINIZIP_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/src/minizip )
    set( MINIZIP_LIBRARIES minizip )
endif()

set( DIGIDOCPP_CONFIG_DIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}/digidocpp" )

if( USE_KEYCHAIN )
    list( APPEND digidocpp_DEFS USE_KEYCHAIN )
    list( APPEND TARGET_LIBRARIES "-framework Security" )
endif()

if( FRAMEWORK )
    list( APPEND digidocpp_DEFS FRAMEWORK )
else()
    list( APPEND digidocpp_DEFS DIGIDOCPP_CONFIG_DIR="${DIGIDOCPP_CONFIG_DIR}" )
endif()

if( LIBDIGIDOC_FOUND )
    list( APPEND digidocpp_SRCS DDoc.cpp )
    include_directories( ${LIBDIGIDOC_INCLUDE_DIR} )
    if( LIBDIGIDOC_LINKED )
        list( APPEND digidocpp_DEFS LINKED_LIBDIGIDOC )
        list( APPEND TARGET_LIBRARIES ${LIBDIGIDOC_LIBRARY} )
    else()
        list( APPEND digidocpp_DEFS DYNAMIC_LIBDIGIDOC )
    endif()
endif()

if( OPENSSL_VERSION LESS "1.0.0" )
    list( APPEND openssl_SRCS
        openssl/ts_asn1.c
        openssl/ts_req_utils.c
        openssl/ts_rsp_utils.c
        openssl/ts_rsp_verify.c
        openssl/ts_verify_ctx.c
    )
    set( OPENSSL_IGNORE
        "-Wno-int-conversion "
        "-Wno-unused-parameter "
        "-Wno-deprecated-declarations "
        "-Wno-incompatible-pointer-types "
        "-Wno-incompatible-pointer-types-discards-qualifiers "
        "-Wno-implicit-function-declaration" )
    string( REPLACE ";" " " OPENSSL_IGNORE ${OPENSSL_IGNORE} )
    #ignore openssl code warnings
    set_source_files_properties( ${openssl_SRCS} PROPERTIES COMPILE_FLAGS ${OPENSSL_IGNORE} )
    list( APPEND digidocpp_SRCS ${openssl_SRCS} )
endif()

configure_file( libdigidocpp.pc.cmake libdigidocpp.pc @ONLY )
configure_file( digidoc-tool.1.cmake digidoc-tool.1 )
configure_file( ${CMAKE_SOURCE_DIR}/etc/digidocpp.conf.cmake digidocpp.conf )

set(SCHEMA_DIR ${CMAKE_SOURCE_DIR}/etc/schema)
set(XML_DIR ${CMAKE_CURRENT_BINARY_DIR}/xml)
XSD_SCHEMA( xsd_SRCS IGNORE ${XML_DIR} ${SCHEMA_DIR}/conf.xsd
     --root-element configuration )
XSD_SCHEMA( xsd_SRCS IGNORE ${XML_DIR} ${SCHEMA_DIR}/OpenDocument_manifest.xsd
    --root-element manifest
    --namespace-map urn:oasis:names:tc:opendocument:xmlns:manifest:1.0=digidoc::manifest )
XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/xmldsig-core-schema.xsd
    --root-element-none
    --namespace-map http://www.w3.org/2000/09/xmldsig\#=digidoc::dsig
    --custom-type ObjectType=/ObjectTypeBase
    --hxx-epilogue \"\#include <xml/ObjectType.h>\" )
XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/XAdES.xsd
    --root-element-none
    --namespace-map http://www.w3.org/2000/09/xmldsig\#=digidoc::dsig
    --namespace-map http://uri.etsi.org/01903/v1.3.2\#=digidoc::xades
    --custom-type AnyType=/AnyTypeBase
    --custom-type UnsignedSignaturePropertiesType=/UnsignedSignaturePropertiesTypeBase
    --ordered-type UnsignedSignaturePropertiesType
    --hxx-epilogue \"\#include <xml/AnyType.h>\"
    --hxx-epilogue \"\#include <xml/UnsignedSignaturePropertiesType.h>\" )
XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/XAdESv141.xsd
    --root-element-none
    --namespace-map http://www.w3.org/2000/09/xmldsig\#=digidoc::dsig
    --namespace-map http://uri.etsi.org/01903/v1.3.2\#=digidoc::xades
    --namespace-map http://uri.etsi.org/01903/v1.4.1\#=digidoc::xadesv141)
XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/ts_102918v010201.xsd
    --root-element XAdESSignatures
    --namespace-map http://www.w3.org/2000/09/xmldsig\#=digidoc::dsig
    --namespace-map http://uri.etsi.org/01903/v1.3.2\#=digidoc::xades
    --namespace-map http://uri.etsi.org/02918/v1.2.1\#=digidoc::asic )
list( APPEND xsd_SRCS xml/ObjectType.cpp xml/AnyType.cpp xml/UnsignedSignaturePropertiesType.cpp )

XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/xml.xsd
    --root-element-none )
XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/ts_119612v010101.xsd
    --root-element TrustServiceStatusList
    --namespace-map http://uri.etsi.org/02231/v2\#=digidoc::tsl
    --namespace-map http://www.w3.org/2000/09/xmldsig\#=digidoc::dsig
    --custom-type AdditionalInformationType=/AdditionalInformationTypeBase
    --hxx-epilogue \"\#include <xml/AdditionalInformationType.h>\" )
#XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/ts_119612v010101_additionaltypes.xsd
#    --root-element-none
#    --namespace-map http://uri.etsi.org/02231/v2/additionaltypes\#=digidoc::tslx
#    --namespace-map http://uri.etsi.org/02231/v2\#=digidoc::tsl
#    --namespace-map http://uri.etsi.org/01903/v1.3.2\#=digidoc::xades )
list( APPEND xsd_SRCS xml/AdditionalInformationType.cpp )
add_executable( embedfile embedfile.cpp )
add_custom_command( OUTPUT tslcert1.cpp tslcert2.cpp tslcert3.cpp
    COMMAND $<TARGET_FILE:embedfile> ${TSL_CERT1} tslcert1 tslcert1.cpp
    COMMAND $<TARGET_FILE:embedfile> ${TSL_CERT2} tslcert2 tslcert2.cpp
    COMMAND $<TARGET_FILE:embedfile> ${TSL_CERT3} tslcert3 tslcert3.cpp
    COMMENT "Generating tslcert1.cpp from ${TSL_CERT1}, tslcert2.cpp from ${TSL_CERT2}, tslcert3.cpp from ${TSL_CERT3}"
)
list( APPEND digidocpp_SRCS tslcert1.cpp tslcert2.cpp tslcert3.cpp )
list( APPEND digidoc-tool_SRCS crypto/Connect.cpp crypto/Digest.cpp )

set( SCHEMA_FILES
    ${SCHEMA_DIR}/conf.xsd
    ${SCHEMA_DIR}/OpenDocument_manifest.xsd
    ${SCHEMA_DIR}/xmldsig-core-schema.xsd
    ${SCHEMA_DIR}/XAdES.xsd
    ${SCHEMA_DIR}/XAdESv141.xsd
    ${SCHEMA_DIR}/ts_102918v010201.xsd
    ${SCHEMA_DIR}/xml.xsd
    ${SCHEMA_DIR}/ts_119612v010101.xsd
#    ${SCHEMA_DIR}/ts_119612v010101_additionaltypes.xsd
)
set( PUBLIC_HEADER
    Conf.h
    Container.h
    DataFile.h
    Exception.h
    Exports.h
    Signature.h
    XmlConf.h
)
set( CRYPTO_HEADER
    crypto/PKCS11Signer.h
    crypto/PKCS12Signer.h
    crypto/Signer.h
    crypto/X509Cert.h
)

set( CRYPTO_SOURCE
    crypto/Connect.cpp
    crypto/Digest.cpp
    crypto/OCSP.cpp
    crypto/PKCS12Signer.cpp
    crypto/TS.cpp
    crypto/X509Cert.cpp
    crypto/X509CertStore.cpp
    crypto/X509Crypto.cpp
)

if( WIN32 )
    list( APPEND CRYPTO_SOURCE crypto/WinSigner.cpp )
    list( APPEND CRYPTO_HEADER crypto/WinSigner.h )
    list( APPEND TARGET_LIBRARIES Crypt32 cryptui ncrypt Ws2_32 )
elseif( APPLE )
    #ignore openssl deprecation warnings
    set_source_files_properties( ${CRYPTO_SOURCE} PROPERTIES COMPILE_FLAGS "-Wno-deprecated-declarations" )
    list( APPEND TARGET_LIBRARIES "-framework CoreFoundation" )
endif()

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${XERCESC_INCLUDE_DIR}
    ${XMLSECURITYC_INCLUDE_DIRS}
    ${XSD_INCLUDE_DIR}
    ${ZLIB_INCLUDE_DIR}
    ${MINIZIP_INCLUDE_DIR}
)

add_library(digidocpp_priv STATIC
    ${xsd_SRCS}
    log.cpp
    crypto/TSL.cpp
    util/File.cpp
    util/DateTime.cpp
)

set_target_properties(digidocpp_priv PROPERTIES
    COMPILE_DEFINITIONS "DIGIDOCPP_CONFIG_DIR=\"${DIGIDOCPP_CONFIG_DIR}\""
    POSITION_INDEPENDENT_CODE YES
)

add_library(digidocpp SHARED
    ${digidocpp_SRCS}
    ${CMAKE_CURRENT_BINARY_DIR}/digidocpp.conf
    ${CMAKE_SOURCE_DIR}/etc/878252.p12
    ${SCHEMA_FILES}
    ${PUBLIC_HEADER}
    ${CRYPTO_HEADER}
    ${CRYPTO_SOURCE}
    ${XML_HEADER}
    libdigidocpp.rc
    BDoc.cpp
    Conf.cpp
    Container.cpp
    XmlConf.cpp
    DataFile.cpp
    Exception.cpp
    Signature.cpp
    SignatureBES.cpp
    SignatureTM.cpp
    SignatureTS.cpp
    SignatureA.cpp
    crypto/PKCS11Signer.cpp
    crypto/Signer.cpp
    util/ZipSerialize.cpp
)

set_target_properties(digidocpp PROPERTIES
    COMPILE_DEFINITIONS "PKCS11_MODULE=\"${PKCS11_MODULE}\";TSA_URL=\"${TSA_URL}\";TSL_URL=\"${TSL_URL}\";${digidocpp_DEFS}"
    VERSION ${MAJOR_VER}.${MINOR_VER}.${RELEASE_VER}
    SOVERSION 0
    PUBLIC_HEADER "${PUBLIC_HEADER}"
    RESOURCE "${CMAKE_CURRENT_BINARY_DIR}/digidocpp.conf;${CMAKE_SOURCE_DIR}/etc/878252.p12"
    FRAMEWORK_VERSION 0
    FRAMEWORK "${FRAMEWORK}"
    MACOSX_FRAMEWORK_IDENTIFIER "ee.ria.digidocpp"
    MACOSX_RPATH YES
)

target_link_libraries(digidocpp digidocpp_priv
    ${OPENSSL_LIBRARIES}
    ${CMAKE_DL_LIBS}
    ${MINIZIP_LIBRARIES}
    ${XERCESC_LIBRARIES}
    ${XMLSECURITYC_LIBRARIES}
    ${ZLIB_LIBRARIES}
    ${TARGET_LIBRARIES}
)

add_executable(digidoc-tool ${digidoc-tool_SRCS} digidoc-tool.rc digidoc-tool.cpp)

set_target_properties(digidoc-tool PROPERTIES
    INSTALL_RPATH "@loader_path/../../../..;@loader_path/../.."
    LINK_LIBRARIES "digidocpp;digidocpp_priv;${CMAKE_THREAD_LIBS_INIT}"
)

if(SWIG_FOUND AND WIN32)
    INCLUDE(${SWIG_USE_FILE})
    INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
    SET(CMAKE_SWIG_FLAGS -dllimport digidoc_csharp -namespace digidoc)
    SET_SOURCE_FILES_PROPERTIES(digidoc.i PROPERTIES CPLUSPLUS ON)
    SET(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR}/csharp)
    SWIG_ADD_MODULE(digidoc_csharp csharp digidoc.i)
    SWIG_LINK_LIBRARIES(digidoc_csharp digidocpp)
    set_target_properties( digidoc_csharp PROPERTIES DEBUG_OUTPUT_NAME "digidoc_csharpd" )
    install(TARGETS digidoc_csharp DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/csharp/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/digidocpp_csharp FILES_MATCHING PATTERN "*.cs")
endif()

install( TARGETS digidocpp
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    RESOURCE DESTINATION ${DIGIDOCPP_CONFIG_DIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/digidocpp
    FRAMEWORK DESTINATION /Library/Frameworks
)

if(WIN32)
    set_target_properties( digidocpp PROPERTIES DEBUG_OUTPUT_NAME "digidocppd" )
    install( DIRECTORY ${PROJECT_BINARY_DIR}/src/ DESTINATION ${CMAKE_INSTALL_LIBDIR} FILES_MATCHING PATTERN "*.pdb" )
endif()

source_group( "Resources" FILES "${CMAKE_CURRENT_BINARY_DIR}/digidocpp.conf;${CMAKE_SOURCE_DIR}/etc/878252.p12" )
source_group( "Resources\\schemas" FILES ${SCHEMA_FILES} )

if( FRAMEWORK )
    add_custom_command( TARGET digidoc-tool POST_BUILD
        COMMAND cp $<TARGET_FILE:digidoc-tool> $<TARGET_FILE_DIR:digidocpp>/Resources )
    set_source_files_properties( ${SCHEMA_FILES} PROPERTIES MACOSX_PACKAGE_LOCATION Resources/schema )
    set_source_files_properties( ${CRYPTO_HEADER} PROPERTIES MACOSX_PACKAGE_LOCATION Headers/crypto )
    get_filename_component( LIBPATH ${XERCESC_LIBRARIES} PATH )
    add_custom_target( embedlibs DEPENDS digidoc-tool
        COMMAND mkdir -p $<TARGET_FILE_DIR:digidocpp>/Libraries
        COMMAND ln -s -f Versions/Current/Libraries $<TARGET_FILE_DIR:digidocpp>/../..
        COMMAND cp ${XERCESC_LIBRARIES} ${XMLSECURITYC_LIBRARIES}
            $<TARGET_FILE_DIR:digidocpp>/Libraries
        COMMAND install_name_tool -id 'libxerces-c.dylib'
            $<TARGET_FILE_DIR:digidocpp>/Libraries/libxerces-c.dylib
        COMMAND install_name_tool -id 'libxml-security-c.dylib'
            -change '${LIBPATH}/libxerces-c-3.1.dylib' '@loader_path/libxerces-c.dylib'
            $<TARGET_FILE_DIR:digidocpp>/Libraries/libxml-security-c.dylib
        COMMAND install_name_tool
            -change '${LIBPATH}/libxerces-c-3.1.dylib' '@loader_path/Libraries/libxerces-c.dylib'
            -change '${LIBPATH}/libxml-security-c.17.dylib' '@loader_path/Libraries/libxml-security-c.dylib'
            $<TARGET_FILE:digidocpp>
        COMMAND install_name_tool
            -change '${LIBPATH}/libxerces-c-3.1.dylib' '@executable_path/../Libraries/libxerces-c.dylib'
            -change '${LIBPATH}/libxml-security-c.17.dylib' '@executable_path/../Libraries/libxml-security-c.dylib'
            $<TARGET_FILE_DIR:digidocpp>/Resources/digidoc-tool
        COMMAND touch $<TARGET_FILE:digidoc-tool>
    )
    add_custom_target( codesign DEPENDS digidoc-tool
        COMMAND for f in $<TARGET_FILE_DIR:digidocpp>/Libraries/*\; do
                codesign -f -s \"$$SIGNCERT\" $$f\;
            done
        COMMAND codesign -f -s \"$$SIGNCERT\" $<TARGET_FILE_DIR:digidocpp>/Resources/digidoc-tool
        COMMAND codesign -f -s \"$$SIGNCERT\" $<TARGET_FILE_DIR:digidocpp>/../..
        COMMAND touch $<TARGET_FILE:digidoc-tool>
    )
    add_custom_target( pkgbuild DEPENDS codesign
        COMMAND make install DESTDIR=install \; pkgbuild
            --root install
            --sign \"$$INSTCERT\"
            ${CMAKE_BINARY_DIR}/libdigidocpp_${VERSION}$ENV{VER_SUFFIX}.pkg
    )
    add_custom_target( zipdebug DEPENDS digidoc-tool
        COMMAND dsymutil -o libdigidocpp.dSYM $<TARGET_FILE:digidocpp>
        COMMAND dsymutil -o libdigidocpp.dSYM $<TARGET_FILE:digidoc-tool>
        COMMAND zip -r ${CMAKE_BINARY_DIR}/libdigidocpp-dbg_${VERSION}$ENV{VER_SUFFIX}.zip libdigidocpp.dSYM
    )
else()
    install( TARGETS digidoc-tool DESTINATION ${CMAKE_INSTALL_BINDIR} )
    install( FILES ${CMAKE_CURRENT_BINARY_DIR}/digidoc-tool.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1 )
    install( FILES ${CMAKE_CURRENT_BINARY_DIR}/libdigidocpp.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig )
    install( FILES ${SCHEMA_FILES} DESTINATION ${DIGIDOCPP_CONFIG_DIR}/schema )
    install( FILES ${CRYPTO_HEADER} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/digidocpp/crypto )
endif()
