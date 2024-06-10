if(NOT MINIZIP_FOUND)
    message(STATUS "MiniZip not found; using bundled copy.")
    add_library(minizip STATIC minizip/zip.c minizip/unzip.c minizip/ioapi.c $<$<C_COMPILER_ID:MSVC>:minizip/iowin32.c>)
    target_compile_options(minizip PRIVATE $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wno-unused-parameter -Wno-unused-value>)
    set_target_properties(minizip PROPERTIES COMPILE_DEFINITIONS "NOUNCRYPT;NOCRYPT" POSITION_INDEPENDENT_CODE YES)
    target_link_libraries(minizip ZLIB::ZLIB)
else()
    add_library(minizip INTERFACE)
    target_link_libraries(minizip INTERFACE PkgConfig::MINIZIP)
endif()

configure_file( libdigidocpp.pc.cmake libdigidocpp.pc @ONLY )
configure_file( ${CMAKE_SOURCE_DIR}/etc/digidocpp.conf.cmake digidocpp.conf )

set(SCHEMA_DIR ${CMAKE_SOURCE_DIR}/etc/schema)
set(XML_DIR ${CMAKE_CURRENT_BINARY_DIR}/xml)
XSD_SCHEMA( xsd_SRCS IGNORE ${XML_DIR} ${SCHEMA_DIR}/OpenDocument_manifest.xsd
    --root-element manifest
    --namespace-map urn:oasis:names:tc:opendocument:xmlns:manifest:1.0=digidoc::manifest )
XSD_SCHEMA( xsd_SRCS IGNORE ${XML_DIR} ${SCHEMA_DIR}/OpenDocument_manifest_v1_2.xsd
    --root-element manifest
    --namespace-map urn:oasis:names:tc:opendocument:xmlns:manifest:1.0=digidoc::manifest_1_2 )
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


file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/tslcerts.h "namespace digidoc {\nstatic const std::vector<X509Cert> tslcerts {\n")
foreach(TSL_CERT ${TSL_CERTS})
    file(READ ${TSL_CERT} filedata HEX)
    string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," filedata ${filedata})
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/tslcerts.h "digidoc::X509Cert({${filedata}}, X509Cert::Pem),\n")
endforeach()
file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/tslcerts.h "};\n}")

set( SCHEMA_FILES
    ${SCHEMA_DIR}/conf.xsd
    ${SCHEMA_DIR}/OpenDocument_manifest.xsd
    ${SCHEMA_DIR}/OpenDocument_manifest_v1_2.xsd
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

add_library(digidocpp_ver INTERFACE)
target_sources(digidocpp_ver INTERFACE libdigidocpp.rc)

add_library(digidocpp_util STATIC
    util/File.cpp
    util/log.cpp
)

target_link_libraries(digidocpp_util PRIVATE $<$<OR:$<PLATFORM_ID:Darwin>,$<PLATFORM_ID:iOS>>:-framework\ CoreFoundation>)

add_library(digidocpp_priv STATIC
    ${xsd_SRCS}
    crypto/Connect.cpp
    crypto/Digest.cpp
    crypto/TSL.cpp
    crypto/X509Crypto.cpp
    util/DateTime.cpp
    xml/AdditionalInformationType.cpp
    xml/AnyType.cpp
    xml/ExtensionType.cpp
    xml/ObjectType.cpp
    xml/SecureDOMParser.cpp
    xml/UnsignedSignaturePropertiesType.cpp
    xml/URIResolver.cpp
    XMLDocument.h
)

set_target_properties(digidocpp_util digidocpp_priv PROPERTIES
    COMPILE_DEFINITIONS digidocpp_EXPORTS
    POSITION_INDEPENDENT_CODE YES
)

target_compile_definitions(digidocpp_priv PUBLIC
    $<$<CXX_COMPILER_ID:AppleClang>:XSD_CXX11_TEMPLATE_ALIAS>
    $<$<CXX_COMPILER_ID:Clang>:XSD_CXX11_TEMPLATE_ALIAS>
)

target_include_directories(digidocpp_priv PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${XSD_INCLUDE_DIR}
)

target_link_libraries(digidocpp_priv
    digidocpp_util
    XmlSecurityC::XmlSecurityC
    ZLIB::ZLIB
    LibXml2::LibXml2
    $<$<C_COMPILER_ID:MSVC>:Ws2_32>
)

add_library(digidocpp
    ${digidocpp_SRCS}
    ${CMAKE_CURRENT_BINARY_DIR}/digidocpp.conf
    ${SCHEMA_FILES}
    ${PUBLIC_HEADER}
    ${CRYPTO_HEADER}
    ${XML_HEADER}
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

set(DIGIDOCPP_CONFIG_DIR ${CMAKE_INSTALL_FULL_SYSCONFDIR}/digidocpp)
set_property(SOURCE util/File.cpp APPEND PROPERTY COMPILE_DEFINITIONS
    DIGIDOCPP_CONFIG_DIR="${DIGIDOCPP_CONFIG_DIR}"
)
set_property(SOURCE Conf.cpp APPEND PROPERTY COMPILE_DEFINITIONS
    PKCS11_MODULE="${PKCS11_MODULE}"
    TSA_URL="${TSA_URL}"
    TSL_URL="${TSL_URL}"
    SIVA_URL="${SIVA_URL}"
)

set_target_properties(digidocpp PROPERTIES
    VERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}
    SOVERSION 1
    PUBLIC_HEADER "${PUBLIC_HEADER}"
    RESOURCE ${CMAKE_CURRENT_BINARY_DIR}/digidocpp.conf
    FRAMEWORK_VERSION 1
    FRAMEWORK "${FRAMEWORK}"
    MACOSX_FRAMEWORK_IDENTIFIER "ee.ria.digidocpp"
    MACOSX_RPATH YES
    COMPILE_DEFINITIONS TARGET_NAME="$<TARGET_NAME:digidocpp>"
)

target_include_directories(digidocpp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(digidocpp PRIVATE ${CMAKE_DL_LIBS} minizip digidocpp_priv digidocpp_ver)

if( BUILD_TOOLS )
    add_executable(digidoc-tool digidoc-tool.rc digidoc-tool.cpp)
    target_link_libraries(digidoc-tool digidocpp digidocpp_priv Threads::Threads)
    configure_file( digidoc-tool.1.cmake digidoc-tool.1 )
endif()

if(PODOFO_FOUND)
    target_sources(digidocpp PRIVATE PDF.cpp SignatureCAdES_B.cpp SignatureCAdES_T.cpp)
    target_include_directories(digidocpp PRIVATE ${PODOFO_INCLUDE_DIR})
    target_link_libraries(digidocpp PRIVATE ${PODOFO_LIBRARIES})
    set_property(SOURCE Container.cpp APPEND PROPERTY COMPILE_DEFINITIONS PDF_SUPPORT)
endif()

if(SWIG_FOUND)
    include(${SWIG_USE_FILE})
    include_directories(${CMAKE_CURRENT_SOURCE_DIR})
    set_property(SOURCE ../libdigidocpp.i PROPERTY CPLUSPLUS ON)
    if(JAVA_INCLUDE_PATH)
        set(CMAKE_SWIG_FLAGS -package ee.ria.libdigidocpp)
        set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR}/java)
        swig_add_library(digidoc_java LANGUAGE java SOURCES ../libdigidocpp.i)
        target_include_directories(digidoc_java PRIVATE ${JAVA_INCLUDE_PATH} $<$<BOOL:${JAVA_INCLUDE_PATH2}>:${JAVA_INCLUDE_PATH2}>)
        target_compile_definitions(digidoc_java PRIVATE TARGET_NAME="$<TARGET_NAME:digidoc_java>")
        target_link_libraries(digidoc_java digidocpp digidocpp_util digidocpp_ver)
        set_target_properties(digidoc_java PROPERTIES
            INSTALL_RPATH $<$<PLATFORM_ID:Darwin>:/Library/Frameworks>
            SWIG_COMPILE_DEFINITIONS $<$<PLATFORM_ID:Windows>:SWIGWIN>
        )
        install(TARGETS digidoc_java DESTINATION $<IF:$<PLATFORM_ID:Darwin>,/Library/Java/Extensions,${CMAKE_INSTALL_LIBDIR}>)
        install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/java/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ee/ria/libdigidocpp FILES_MATCHING PATTERN "*.java")
        if(WIN32)
            install(FILES $<TARGET_PDB_FILE:digidoc_java> DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
        endif()
    endif()
    if(Python3_FOUND)
        set(CMAKE_SWIG_FLAGS -py3)
        set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR})
        swig_add_library(digidoc_python LANGUAGE python SOURCES ../libdigidocpp.i)
        target_compile_definitions(digidoc_python PRIVATE TARGET_NAME="$<TARGET_NAME:digidoc_python>")
        target_link_libraries(digidoc_python digidocpp digidocpp_util digidocpp_ver Python3::Module)
        #configure_file(setup.py.cmake setup.py)
        #install(CODE "execute_process(COMMAND python3 ${CMAKE_CURRENT_BINARY_DIR}/setup.py install)")
        if(NOT Python3_SITELIB)
            execute_process(COMMAND /usr/bin/python3 -c
                "from distutils import sysconfig;print(sysconfig.get_python_lib(plat_specific=False,standard_lib=False))"
                OUTPUT_VARIABLE Python3_SITELIB OUTPUT_STRIP_TRAILING_WHITESPACE)
        endif()
        if(WIN32)
            set(Python3_SITELIB ${CMAKE_INSTALL_BINDIR})
            install(FILES $<TARGET_PDB_FILE:digidoc_python> DESTINATION ${Python3_SITELIB} OPTIONAL)
        else()
            set_target_properties(digidoc_python PROPERTIES SUFFIX .so)
        endif()
        set_target_properties(digidoc_python PROPERTIES
            INSTALL_RPATH $<$<PLATFORM_ID:Darwin>:/Library/Frameworks>
            SWIG_COMPILE_DEFINITIONS $<$<PLATFORM_ID:Windows>:SWIGWIN>
        )
        install(TARGETS digidoc_python DESTINATION ${Python3_SITELIB})
        install(FILES ${CMAKE_CURRENT_BINARY_DIR}/digidoc.py DESTINATION ${Python3_SITELIB})
    endif()

    set(CMAKE_SWIG_FLAGS -dllimport digidoc_csharp -namespace digidoc)
    set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR}/csharp)
    swig_add_library(digidoc_csharp LANGUAGE csharp SOURCES ../libdigidocpp.i)
    target_compile_definitions(digidoc_csharp PRIVATE TARGET_NAME="$<TARGET_NAME:digidoc_csharp>")
    target_link_libraries(digidoc_csharp digidocpp digidocpp_util digidocpp_ver)
    set_target_properties(digidoc_csharp PROPERTIES
        SWIG_COMPILE_DEFINITIONS $<$<PLATFORM_ID:Windows>:SWIGWIN>
        INSTALL_RPATH $<$<PLATFORM_ID:Darwin>:/Library/Frameworks>
        PREFIX "${CMAKE_SHARED_LIBRARY_PREFIX}"
    )
    install(TARGETS digidoc_csharp DESTINATION ${CMAKE_INSTALL_LIBDIR})
    install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/csharp/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/digidocpp_csharp FILES_MATCHING PATTERN "*.cs")
    if(WIN32)
        install(FILES $<TARGET_PDB_FILE:digidoc_csharp> DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
    endif()
endif()

install( TARGETS digidocpp
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    RESOURCE DESTINATION ${DIGIDOCPP_CONFIG_DIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/digidocpp
    FRAMEWORK DESTINATION ${FRAMEWORK_DESTINATION}
)

if(WIN32)
    list(APPEND CRYPTO_HEADER crypto/WinSigner.h)
    target_sources(digidocpp PRIVATE crypto/WinSigner.cpp)
    target_compile_options(digidocpp PUBLIC "/guard:cf")
    target_link_options(digidocpp PUBLIC "/guard:cf")
    target_link_libraries(digidocpp PRIVATE Crypt32 cryptui ncrypt Ws2_32)
    install(FILES $<TARGET_PDB_FILE:digidocpp> $<TARGET_PDB_FILE:digidoc-tool> DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
    if(SIGNCERT)
        foreach(TARGET digidocpp digidoc-tool digidoc_java digidoc_csharp digidoc_python)
            if(CROSSSIGNCERT)
                target_link_options(${TARGET} PRIVATE "/INTEGRITYCHECK")
            endif()
            add_custom_command(TARGET ${TARGET} POST_BUILD
                COMMAND signtool.exe sign /a /v /s MY /n "${SIGNCERT}" /fd SHA256 /du http://installer.id.ee
                    "$<$<BOOL:${CROSSSIGNCERT}>:/ph;/ac;${CROSSSIGNCERT}>"
                    /tr http://sha256timestamp.ws.symantec.com/sha256/timestamp /td SHA256 $<TARGET_FILE:${TARGET}>
                COMMAND_EXPAND_LISTS
            )
        endforeach()
    endif()
endif()

source_group(Resources FILES ${CMAKE_CURRENT_BINARY_DIR}/digidocpp.conf)
source_group(Resources/schemas FILES ${SCHEMA_FILES})

if( FRAMEWORK )
    install(TARGETS minizip DESTINATION ${CMAKE_INSTALL_LIBDIR}) # for example ios application
    set_source_files_properties( ${SCHEMA_FILES} PROPERTIES MACOSX_PACKAGE_LOCATION Resources/schema )
    set_source_files_properties( ${CRYPTO_HEADER} PROPERTIES MACOSX_PACKAGE_LOCATION Headers/crypto )
    list( GET XmlSecurityC_LIBRARIES 0 LIBPATH )
    get_filename_component( LIBPATH ${LIBPATH} PATH )
    add_custom_target( embedlibs DEPENDS digidocpp $<TARGET_NAME_IF_EXISTS:digidoc-tool>
        COMMAND mkdir -p $<TARGET_FILE_DIR:digidocpp>/Libraries
        COMMAND ln -s -f Versions/Current/Libraries $<TARGET_BUNDLE_DIR:digidocpp>
        COMMAND cp ${XmlSecurityC_LIBRARIES} $<TARGET_FILE_DIR:digidocpp>/Libraries
        COMMAND chmod 644 $<TARGET_FILE_DIR:digidocpp>/Libraries/*
        COMMAND install_name_tool -id 'libcrypto.dylib'
            $<TARGET_FILE_DIR:digidocpp>/Libraries/libcrypto.dylib
        COMMAND install_name_tool -id 'libssl.dylib'
            -change '${LIBPATH}/libcrypto.3.dylib' '@loader_path/libcrypto.dylib'
            $<TARGET_FILE_DIR:digidocpp>/Libraries/libssl.dylib
        COMMAND install_name_tool -id 'libxerces-c.dylib'
            $<TARGET_FILE_DIR:digidocpp>/Libraries/libxerces-c.dylib
        COMMAND install_name_tool -id 'libxalanMsg.dylib'
            -change '${LIBPATH}/libxerces-c-3.2.dylib' '@loader_path/libxerces-c.dylib'
            $<TARGET_FILE_DIR:digidocpp>/Libraries/libxalanMsg.dylib
        COMMAND install_name_tool -id 'libxalan-c.dylib'
            -change '${LIBPATH}/libxalanMsg.112.dylib' '@loader_path/libxalanMsg.dylib'
            -change '${LIBPATH}/libxerces-c-3.2.dylib' '@loader_path/libxerces-c.dylib'
            $<TARGET_FILE_DIR:digidocpp>/Libraries/libxalan-c.dylib
        COMMAND install_name_tool -id 'libxml-security-c.dylib'
            -change '${LIBPATH}/libcrypto.3.dylib' '@loader_path/libcrypto.dylib'
            -change '${LIBPATH}/libssl.3.dylib' '@loader_path/libssl.dylib'
            -change '${LIBPATH}/libxerces-c-3.2.dylib' '@loader_path/libxerces-c.dylib'
            -change '${LIBPATH}/libxalan-c.112.dylib' '@loader_path/libxalan-c.dylib'
            -change '${LIBPATH}/libxalanMsg.112.dylib' '@loader_path/libxalanMsg.dylib'
            $<TARGET_FILE_DIR:digidocpp>/Libraries/libxml-security-c.dylib
        COMMAND install_name_tool
            -change '${LIBPATH}/libcrypto.3.dylib' '@loader_path/Libraries/libcrypto.dylib'
            -change '${LIBPATH}/libssl.3.dylib' '@loader_path/Libraries/libssl.dylib'
            -change '${LIBPATH}/libxerces-c-3.2.dylib' '@loader_path/Libraries/libxerces-c.dylib'
            -change '${LIBPATH}/libxml-security-c.20.dylib' '@loader_path/Libraries/libxml-security-c.dylib'
            -change '${LIBPATH}/libxalan-c.112.dylib' '@loader_path/Libraries/libxalan-c.dylib'
            $<TARGET_FILE:digidocpp>
    )
    if(BUILD_TOOLS)
        add_custom_command(TARGET digidoc-tool POST_BUILD
            COMMAND cp $<TARGET_FILE:digidoc-tool> $<TARGET_FILE_DIR:digidocpp>/Resources)
        add_custom_command(TARGET embedlibs POST_BUILD
            COMMAND install_name_tool
                -change '${LIBPATH}/libcrypto.3.dylib' '@executable_path/../Libraries/libcrypto.dylib'
                -change '${LIBPATH}/libssl.3.dylib' '@executable_path/../Libraries/libssl.dylib'
                -change '${LIBPATH}/libxerces-c-3.2.dylib' '@executable_path/../Libraries/libxerces-c.dylib'
                -change '${LIBPATH}/libxml-security-c.20.dylib' '@executable_path/../Libraries/libxml-security-c.dylib'
                -change '${LIBPATH}/libxalan-c.112.dylib' '@executable_path/../Libraries/libxalan-c.dylib'
                $<TARGET_FILE_DIR:digidocpp>/Resources/digidoc-tool
            COMMAND touch $<TARGET_FILE:digidoc-tool>
        )
    endif()
    if(IOS)
        add_custom_command(TARGET digidocpp POST_BUILD
            COMMAND /usr/libexec/PlistBuddy -c "Add :MinimumOSVersion string ${CMAKE_OSX_DEPLOYMENT_TARGET}" $<TARGET_FILE_DIR:digidocpp>/Info.plist)
    endif()
    add_custom_target(codesign DEPENDS digidocpp $<TARGET_NAME_IF_EXISTS:digidoc-tool>
        COMMAND codesign -f -s "Developer ID Application: ${SIGNCERT}"
            $<TARGET_FILE_DIR:digidocpp>/Libraries/*
            $<$<TARGET_EXISTS:digidoc-tool>:$<TARGET_FILE_DIR:digidocpp>/Resources/digidoc-tool>
            $<TARGET_BUNDLE_DIR:digidocpp>
        COMMAND touch $<TARGET_FILE:digidocpp> $<$<TARGET_EXISTS:digidoc-tool>:$<TARGET_FILE:digidoc-tool>>
    )
    add_custom_target(pkgbuild DEPENDS digidocpp $<TARGET_NAME_IF_EXISTS:digidoc-tool>
        COMMAND make install DESTDIR=install
        COMMAND pkgbuild --root install "$<$<BOOL:${SIGNCERT}>:--sign;${SIGNCERT}>"
            ${CMAKE_BINARY_DIR}/libdigidocpp_${VERSION}$ENV{VER_SUFFIX}.pkg
        COMMAND_EXPAND_LISTS
    )
    add_custom_target(zipdebug DEPENDS digidocpp $<TARGET_NAME_IF_EXISTS:digidoc-tool>
        COMMAND dsymutil -o libdigidocpp.dSYM $<TARGET_FILE:digidocpp>
            $<$<TARGET_EXISTS:digidoc-tool>:$<TARGET_FILE:digidoc-tool>>
        COMMAND zip -r ${CMAKE_BINARY_DIR}/libdigidocpp-dbg_${VERSION}$ENV{VER_SUFFIX}.zip libdigidocpp.dSYM
    )
else()
    if(NOT ${BUILD_SHARED_LIBS})
        install( TARGETS minizip digidocpp_priv digidocpp_util DESTINATION ${CMAKE_INSTALL_LIBDIR} )
    endif()
    if( BUILD_TOOLS )
        install( TARGETS digidoc-tool DESTINATION ${CMAKE_INSTALL_BINDIR} )
        install( FILES ${CMAKE_CURRENT_BINARY_DIR}/digidoc-tool.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1 )
    endif()
    install( FILES ${CMAKE_CURRENT_BINARY_DIR}/libdigidocpp.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig )
    install( FILES ${SCHEMA_FILES} DESTINATION ${DIGIDOCPP_CONFIG_DIR}/schema )
    install( FILES ${CRYPTO_HEADER} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/digidocpp/crypto )
endif()
