if(NOT MINIZIP_FOUND)
    message(STATUS "MiniZip not found; using bundled copy.")
    if(WIN32)
        list( APPEND MINIZIP_SRCS minizip/iowin32.c )
    endif()
    add_library( minizip STATIC minizip/zip.c minizip/unzip.c minizip/ioapi.c ${MINIZIP_SRCS} )
    if(CMAKE_COMPILER_IS_GNUCC OR __COMPILER_GNU)
        set_target_properties( minizip PROPERTIES COMPILE_FLAGS "-fPIC -Wno-unused-parameter" )
    endif()
    set_target_properties( minizip PROPERTIES COMPILE_DEFINITIONS "NOUNCRYPT;NOCRYPT" )
    set( MINIZIP_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/src/minizip )
    set( MINIZIP_LIBRARIES minizip )
endif()

set( DIGIDOCPP_CONFIG_DIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}/digidocpp" )

if( USE_KEYCHAIN )
    list( APPEND digidocpp_DEFS USE_KEYCHAIN )
    list( APPEND TARGET_LIBRARIES "-framework Security" )
endif()

if( LIBDIGIDOC_FOUND )
    list( APPEND digidocpp_SRCS DDoc.cpp )
    include_directories( ${LIBDIGIDOC_INCLUDE_DIR} )
    if( LIBDIGIDOC_LINKED )
        list( APPEND digidocpp_DEFS LINKED_LIBDIGIDOC )
        list( APPEND TARGET_LIBRARIES ${LIBDIGIDOC_LIBRARY} )
        if( ${BUILD_TYPE} STREQUAL "STATIC" )
            find_package(Iconv)
            find_package(LibXml2)
            list( APPEND TARGET_LIBRARIES ${ICONV_LIBRARIES} ${LIBXML2_LIBRARIES} )
        endif()
    else()
        list( APPEND digidocpp_DEFS DYNAMIC_LIBDIGIDOC )
    endif()
endif()

if(ANDROID)
    find_package(Iconv)
    list( APPEND TARGET_LIBRARIES ${ICONV_LIBRARIES} )
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
XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/XAdES01903v132-201601.xsd
    --root-element-none
    --namespace-map http://www.w3.org/2000/09/xmldsig\#=digidoc::dsig
    --namespace-map http://uri.etsi.org/01903/v1.3.2\#=digidoc::xades
    --custom-type AnyType=/AnyTypeBase
    --custom-type UnsignedSignaturePropertiesType=/UnsignedSignaturePropertiesTypeBase
    --ordered-type UnsignedSignaturePropertiesType
    --hxx-epilogue \"\#include <xml/AnyType.h>\"
    --hxx-epilogue \"\#include <xml/UnsignedSignaturePropertiesType.h>\" )
XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/XAdES01903v141-201601.xsd
    --root-element-none
    --namespace-map http://www.w3.org/2000/09/xmldsig\#=digidoc::dsig
    --namespace-map http://uri.etsi.org/01903/v1.3.2\#=digidoc::xades
    --namespace-map http://uri.etsi.org/01903/v1.4.1\#=digidoc::xadesv141)
XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/en_31916201v010101.xsd
    --root-element XAdESSignatures
    --namespace-map http://www.w3.org/2000/09/xmldsig\#=digidoc::dsig
    --namespace-map http://uri.etsi.org/01903/v1.3.2\#=digidoc::xades
    --namespace-map http://uri.etsi.org/02918/v1.2.1\#=digidoc::asic )
XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/OpenDocument_dsig.xsd
    --root-element document-signatures
    --namespace-map urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0=digidoc::asic
    --namespace-map http://www.w3.org/2000/09/xmldsig\#=digidoc::dsig)
XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/xml.xsd
    --root-element-none )
XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/ts_119612v020201_201601xsd.xsd
    --root-element TrustServiceStatusList
    --namespace-map http://uri.etsi.org/02231/v2\#=digidoc::tsl
    --namespace-map http://www.w3.org/2000/09/xmldsig\#=digidoc::dsig
    --custom-type AdditionalInformationType=/AdditionalInformationTypeBase
    --custom-type ExtensionType=/ExtensionTypeBase
    --hxx-epilogue \"\#include <xml/ExtensionType.h>\"
    --hxx-epilogue \"\#include <xml/AdditionalInformationType.h>\" )
XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/ts_119612v020101_additionaltypes_xsd.xsd
    --root-element-none
    --namespace-map http://uri.etsi.org/02231/v2\#=digidoc::tsl
    --namespace-map http://uri.etsi.org/02231/v2/additionaltypes\#=digidoc::tsl
    --namespace-map http://uri.etsi.org/01903/v1.3.2\#=digidoc::xades )
XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/ts_119612v020101_sie_xsd.xsd
    --root-element-none
    --accessor-regex /assert/assert_/
    --modifier-regex /assert/assert_/
    --namespace-map http://uri.etsi.org/02231/v2\#=digidoc::tsl
    --namespace-map http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/\#=digidoc::tsl
    --namespace-map http://uri.etsi.org/01903/v1.3.2\#=digidoc::xades )

if(WIN32)
    add_executable(embedfile embedfile.cpp)
endif()
set(COUNT 0)
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/tslcerts.h "")
foreach(TSL_CERT ${TSL_CERTS})
    math(EXPR COUNT "${COUNT}+1")
    set(BASE "tslcert${COUNT}")
    list(APPEND digidocpp_SRCS ${CMAKE_CURRENT_BINARY_DIR}/${BASE}.h)
    if(WIN32)
        add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${BASE}.h
            COMMAND $<TARGET_FILE:embedfile> ${TSL_CERT} ${BASE}_crt ${BASE}.h
            COMMENT "Generating ${BASE}.h from ${TSL_CERT}"
            )
    else()
        add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${BASE}.h
            COMMAND ln -sf ${TSL_CERT} ${BASE}.crt
            COMMAND xxd -i ${BASE}.crt ${BASE}.h
            COMMENT "Generating ${BASE}.h from ${TSL_CERT}"
            )
    endif()
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/tslcerts.h "#include \"${BASE}.h\"\n")
endforeach()
file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/tslcerts.h "static const std::vector<X509Cert> tslcerts {\n")

set(COUNT 0)
foreach(TSL_CERT ${TSL_CERTS})
    math(EXPR COUNT "${COUNT}+1")
    set(BASE "tslcert${COUNT}")
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/tslcerts.h "digidoc::X509Cert(${BASE}_crt, ${BASE}_crt_len, X509Cert::Pem),\n")
endforeach()
file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/tslcerts.h "};")

set( SCHEMA_FILES
    ${SCHEMA_DIR}/conf.xsd
    ${SCHEMA_DIR}/OpenDocument_manifest.xsd
    ${SCHEMA_DIR}/xmldsig-core-schema.xsd
    ${SCHEMA_DIR}/XAdES01903v132-201601.xsd
    ${SCHEMA_DIR}/XAdES01903v132-201601-relaxed.xsd
    ${SCHEMA_DIR}/XAdES01903v141-201601.xsd
    ${SCHEMA_DIR}/en_31916201v010101.xsd
    ${SCHEMA_DIR}/xml.xsd
    ${SCHEMA_DIR}/ts_119612v020201_201601xsd.xsd
    ${SCHEMA_DIR}/ts_119612v020101_additionaltypes_xsd.xsd
    ${SCHEMA_DIR}/ts_119612v020101_sie_xsd.xsd
    ${SCHEMA_DIR}/OpenDocument_dsig.xsd
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

if( WIN32 )
    list( APPEND digidocpp_SRCS crypto/WinSigner.cpp )
    list( APPEND CRYPTO_HEADER crypto/WinSigner.h )
    list( APPEND TARGET_LIBRARIES Crypt32 cryptui ncrypt Ws2_32 )
elseif( APPLE )
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

if( PODOFO_FOUND )
    list( APPEND digidocpp_SRCS
        PDF.cpp
        SignatureCAdES_B.cpp
        SignatureCAdES_T.cpp
    )
    list( APPEND TARGET_LIBRARIES ${PODOFO_LIBRARIES} )
    list( APPEND digidocpp_DEFS PDF_SUPPORT )
    include_directories( ${PODOFO_INCLUDE_DIR} )
endif()

add_library(digidocpp_priv STATIC
    ${xsd_SRCS}
    log.cpp
    crypto/Connect.cpp
    crypto/Digest.cpp
    crypto/TSL.cpp
    crypto/X509Crypto.cpp
    util/File.cpp
    util/DateTime.cpp
    xml/AdditionalInformationType.cpp
    xml/AnyType.cpp
    xml/ExtensionType.cpp
    xml/ObjectType.cpp
    xml/SecureDOMParser.cpp
    xml/UnsignedSignaturePropertiesType.cpp
    xml/URIResolver.cpp
)

set_target_properties(digidocpp_priv PROPERTIES
    COMPILE_DEFINITIONS "DIGIDOCPP_CONFIG_DIR=\"${DIGIDOCPP_CONFIG_DIR}\""
    POSITION_INDEPENDENT_CODE YES
)

add_library(digidocpp ${BUILD_TYPE}
    ${digidocpp_SRCS}
    ${CMAKE_CURRENT_BINARY_DIR}/digidocpp.conf
    ${CMAKE_SOURCE_DIR}/etc/878252.p12
    ${CMAKE_SOURCE_DIR}/etc/798.p12
    ${SCHEMA_FILES}
    ${PUBLIC_HEADER}
    ${CRYPTO_HEADER}
    ${XML_HEADER}
    libdigidocpp.rc
    Container.cpp
    ASiContainer.cpp
    ASiC_E.cpp
    ASiC_S.cpp
    SiVaContainer.cpp
    Conf.cpp
    XmlConf.cpp
    DataFile.cpp
    Exception.cpp
    Signature.cpp
    SignatureXAdES_B.cpp
    SignatureXAdES_T.cpp
    SignatureXAdES_LT.cpp
    SignatureXAdES_LTA.cpp
    SignatureTST.cpp
    crypto/OCSP.cpp
    crypto/PKCS11Signer.cpp
    crypto/PKCS12Signer.cpp
    crypto/Signer.cpp
    crypto/TS.cpp
    crypto/X509Cert.cpp
    crypto/X509CertStore.cpp
    util/ZipSerialize.cpp
)

set_target_properties(digidocpp PROPERTIES
    COMPILE_DEFINITIONS "PKCS11_MODULE=\"${PKCS11_MODULE}\";TSA_URL=\"${TSA_URL}\";TSL_URL=\"${TSL_URL}\";SIVA_URL=\"${SIVA_URL}\";${digidocpp_DEFS}"
    VERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}
    SOVERSION 1
    PUBLIC_HEADER "${PUBLIC_HEADER}"
    RESOURCE "${CMAKE_CURRENT_BINARY_DIR}/digidocpp.conf;${CMAKE_SOURCE_DIR}/etc/878252.p12;${CMAKE_SOURCE_DIR}/etc/798.p12"
    FRAMEWORK_VERSION 1
    FRAMEWORK "${FRAMEWORK}"
    MACOSX_FRAMEWORK_IDENTIFIER "ee.ria.digidocpp"
    MACOSX_RPATH YES
)

target_link_libraries(digidocpp digidocpp_priv
    ${CMAKE_DL_LIBS}
    ${MINIZIP_LIBRARIES}
    ${XMLSECURITYC_LIBRARIES}
    $<$<STREQUAL:${BUILD_TYPE},STATIC>:${XALANMSG_LIBRARY}>
    ${XERCESC_LIBRARIES}
    ${TARGET_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${ZLIB_LIBRARIES}
)

if( BUILD_TOOLS )
    add_executable(digidoc-tool digidoc-tool.rc digidoc-tool.cpp)
    target_link_libraries(digidoc-tool digidocpp ${CMAKE_THREAD_LIBS_INIT})
endif()

if(SWIG_FOUND)
    include(${SWIG_USE_FILE})
    set_property(SOURCE ../libdigidocpp.i PROPERTY CPLUSPLUS ON)
    if(JAVA_INCLUDE_PATH)
        set(CMAKE_SWIG_FLAGS -package ee.ria.libdigidocpp)
        set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR}/java)
        swig_add_library(digidoc_java TYPE SHARED LANGUAGE java SOURCES ../libdigidocpp.i)
        swig_link_libraries(digidoc_java digidocpp)
        set_target_properties(digidoc_java PROPERTIES DEBUG_OUTPUT_NAME "digidoc_javad")
        target_include_directories(digidoc_java PRIVATE ${JAVA_INCLUDE_PATH})
        if(JAVA_INCLUDE_PATH2)
            target_include_directories(digidoc_java PRIVATE ${JAVA_INCLUDE_PATH2})
        endif()
        install(TARGETS digidoc_java DESTINATION ${CMAKE_INSTALL_LIBDIR})
        install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/java/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ee/ria/libdigidocpp FILES_MATCHING PATTERN "*.java")
    endif()
    if(WIN32)
        set(CMAKE_SWIG_FLAGS -dllimport digidoc_csharp -namespace digidoc)
        set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR}/csharp)
        swig_add_library(digidoc_csharp TYPE SHARED LANGUAGE csharp SOURCES ../libdigidocpp.i)
        swig_link_libraries(digidoc_csharp digidocpp)
        set_target_properties(digidoc_csharp PROPERTIES DEBUG_OUTPUT_NAME "digidoc_csharpd")
        install(TARGETS digidoc_csharp DESTINATION ${CMAKE_INSTALL_BINDIR})
        install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/csharp/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/digidocpp_csharp FILES_MATCHING PATTERN "*.cs")
    endif()
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
    install(FILES
        $<TARGET_PDB_FILE:digidocpp>
        $<TARGET_PDB_FILE:digidoc-tool>
        $<TARGET_PDB_FILE:digidoc_csharp>
        $<TARGET_PDB_FILE:digidoc_java>
        DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
endif()

source_group( "Resources" FILES "${CMAKE_CURRENT_BINARY_DIR}/digidocpp.conf;${CMAKE_SOURCE_DIR}/etc/878252.p12;${CMAKE_SOURCE_DIR}/etc/798.p12" )
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
        COMMAND cp ${OPENSSL_LIBRARIES} ${XERCESC_LIBRARIES} ${XMLSECURITYC_LIBRARIES} ${XALANMSG_LIBRARY}
            $<TARGET_FILE_DIR:digidocpp>/Libraries
        COMMAND chmod 644 $<TARGET_FILE_DIR:digidocpp>/Libraries/*
        COMMAND install_name_tool -id 'libcrypto.dylib'
            $<TARGET_FILE_DIR:digidocpp>/Libraries/libcrypto.dylib
        COMMAND install_name_tool -id 'libssl.dylib'
            -change '${LIBPATH}/libcrypto.1.0.0.dylib' '@loader_path/libcrypto.dylib'
            $<TARGET_FILE_DIR:digidocpp>/Libraries/libssl.dylib
        COMMAND install_name_tool -id 'libxerces-c.dylib'
            $<TARGET_FILE_DIR:digidocpp>/Libraries/libxerces-c.dylib
        COMMAND install_name_tool -id 'libxalanMsg.dylib'
            $<TARGET_FILE_DIR:digidocpp>/Libraries/libxalanMsg.dylib
        COMMAND install_name_tool -id 'libxalan-c.dylib'
            -change '${LIBPATH}/libxalanMsg.111.0.dylib' '@loader_path/libxalanMsg.dylib'
            -change '${LIBPATH}/libxerces-c-3.2.dylib' '@loader_path/libxerces-c.dylib'
            $<TARGET_FILE_DIR:digidocpp>/Libraries/libxalan-c.dylib
        COMMAND install_name_tool -id 'libxml-security-c.dylib'
            -change '${LIBPATH}/libcrypto.1.0.0.dylib' '@loader_path/libcrypto.dylib'
            -change '${LIBPATH}/libssl.1.0.0.dylib' '@loader_path/libssl.dylib'
            -change '${LIBPATH}/libxerces-c-3.2.dylib' '@loader_path/libxerces-c.dylib'
            -change '${LIBPATH}/libxalan-c.111.0.dylib' '@loader_path/libxalan-c.dylib'
            -change '${LIBPATH}/libxalanMsg.111.0.dylib' '@loader_path/libxalanMsg.dylib'
            $<TARGET_FILE_DIR:digidocpp>/Libraries/libxml-security-c.dylib
        COMMAND install_name_tool
            -change '${LIBPATH}/libcrypto.1.0.0.dylib' '@loader_path/Libraries/libcrypto.dylib'
            -change '${LIBPATH}/libssl.1.0.0.dylib' '@loader_path/Libraries/libssl.dylib'
            -change '${LIBPATH}/libxerces-c-3.2.dylib' '@loader_path/Libraries/libxerces-c.dylib'
            -change '${LIBPATH}/libxml-security-c.17.dylib' '@loader_path/Libraries/libxml-security-c.dylib'
            -change '${LIBPATH}/libxalan-c.111.0.dylib' '@loader_path/Libraries/libxalan-c.dylib'
            $<TARGET_FILE:digidocpp>
        COMMAND install_name_tool
            -change '${LIBPATH}/libcrypto.1.0.0.dylib' '@executable_path/../Libraries/libcrypto.dylib'
            -change '${LIBPATH}/libssl.1.0.0.dylib' '@executable_path/../Libraries/libssl.dylib'
            -change '${LIBPATH}/libxerces-c-3.2.dylib' '@executable_path/../Libraries/libxerces-c.dylib'
            -change '${LIBPATH}/libxml-security-c.17.dylib' '@executable_path/../Libraries/libxml-security-c.dylib'
            -change '${LIBPATH}/libxalan-c.111.0.dylib' '@executable_path/../Libraries/libxalan-c.dylib'
            $<TARGET_FILE_DIR:digidocpp>/Resources/digidoc-tool
        COMMAND touch $<TARGET_FILE:digidoc-tool>
    )
    add_custom_target( codesign DEPENDS digidoc-tool
        COMMAND codesign -f -s ${SIGNCERT}
            $<TARGET_FILE_DIR:digidocpp>/Libraries/*
            $<TARGET_FILE_DIR:digidocpp>/Resources/digidoc-tool
            $<TARGET_FILE_DIR:digidocpp>/../..
        COMMAND touch $<TARGET_FILE:digidoc-tool>
    )
    if(INSTCERT)
        set(PKGEXTRA --sign ${INSTCERT})
    endif()
    add_custom_target( pkgbuild DEPENDS digidoc-tool
        COMMAND make install DESTDIR=install
        COMMAND pkgbuild --root install ${PKGEXTRA}
            ${CMAKE_BINARY_DIR}/libdigidocpp_${VERSION}$ENV{VER_SUFFIX}.pkg
    )
    add_custom_target( zipdebug DEPENDS digidoc-tool
        COMMAND dsymutil -o libdigidocpp.dSYM $<TARGET_FILE:digidocpp>
        COMMAND dsymutil -o libdigidocpp.dSYM $<TARGET_FILE:digidoc-tool>
        COMMAND zip -r ${CMAKE_BINARY_DIR}/libdigidocpp-dbg_${VERSION}$ENV{VER_SUFFIX}.zip libdigidocpp.dSYM
    )
else()
    if( ${BUILD_TYPE} STREQUAL "STATIC" )
        install( TARGETS minizip digidocpp_priv DESTINATION ${CMAKE_INSTALL_LIBDIR} )
    endif()
    if( BUILD_TOOLS )
        install( TARGETS digidoc-tool DESTINATION ${CMAKE_INSTALL_BINDIR} )
        install( FILES ${CMAKE_CURRENT_BINARY_DIR}/digidoc-tool.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1 )
    endif()
    install( FILES ${CMAKE_CURRENT_BINARY_DIR}/libdigidocpp.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig )
    install( FILES ${SCHEMA_FILES} DESTINATION ${DIGIDOCPP_CONFIG_DIR}/schema )
    install( FILES ${CRYPTO_HEADER} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/digidocpp/crypto )
endif()
