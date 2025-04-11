if(TARGET PkgConfig::MINIZIP)
    add_library(minizip ALIAS PkgConfig::MINIZIP)
else()
    message(STATUS "MiniZip not found; using bundled copy.")
    add_library(minizip STATIC minizip/zip.c minizip/unzip.c minizip/ioapi.c $<$<C_COMPILER_ID:MSVC>:minizip/iowin32.c>)
    target_compile_options(minizip PRIVATE $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wno-unused-parameter -Wno-unused-value>)
    set_target_properties(minizip PROPERTIES COMPILE_DEFINITIONS "NOUNCRYPT;NOCRYPT" POSITION_INDEPENDENT_CODE YES)
    target_link_libraries(minizip ZLIB::ZLIB)
endif()

set_env(BUILD_NUMBER 0)
set(VERSION ${PROJECT_VERSION}.${BUILD_NUMBER})

configure_file( libdigidocpp.pc.cmake libdigidocpp.pc @ONLY )
configure_file( ${CMAKE_SOURCE_DIR}/etc/digidocpp.conf.cmake digidocpp.conf )

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/tslcerts.h "namespace digidoc {\nstatic const std::vector<X509Cert> tslcerts {\n")
foreach(TSL_CERT ${TSL_CERTS})
    file(READ ${TSL_CERT} filedata HEX)
    string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," filedata ${filedata})
    file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/tslcerts.h "digidoc::X509Cert({${filedata}}, X509Cert::Pem),\n")
endforeach()
file(APPEND ${CMAKE_CURRENT_BINARY_DIR}/tslcerts.h "};\n}")

set(SCHEMA_DIR ${CMAKE_SOURCE_DIR}/etc/schema)
set( SCHEMA_FILES
    ${SCHEMA_DIR}/conf.xsd
    ${SCHEMA_DIR}/OpenDocument_manifest_v1_2.xsd
    ${SCHEMA_DIR}/xmldsig-core-schema.xsd
    ${SCHEMA_DIR}/XAdES01903v132-201601.xsd
    ${SCHEMA_DIR}/XAdES01903v141-201601.xsd
    ${SCHEMA_DIR}/en_31916201v010101.xsd
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
target_compile_definitions(digidocpp_ver INTERFACE VERSION_STR="${VERSION}")
if(WIN32)
    target_compile_definitions(digidocpp_ver INTERFACE
        UNICODE _CRT_SECURE_NO_WARNINGS _SCL_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN
        VERSION=${PROJECT_VERSION_MAJOR},${PROJECT_VERSION_MINOR},${PROJECT_VERSION_PATCH},${BUILD_NUMBER}
        TARGET_NAME="$<TARGET_PROPERTY:NAME>"
        $<$<STREQUAL:$<TARGET_PROPERTY:TYPE>,EXECUTABLE>:APP>
    )
endif()
target_sources(digidocpp_ver INTERFACE libdigidocpp.rc)

add_library(digidocpp_util STATIC
    util/File.cpp
    util/log.cpp
)

target_link_libraries(digidocpp_util PUBLIC digidocpp_ver PRIVATE $<$<OR:$<PLATFORM_ID:Darwin>,$<PLATFORM_ID:iOS>>:-framework\ CoreFoundation>)

add_library(digidocpp_priv STATIC
    crypto/Connect.cpp
    crypto/Digest.cpp
    crypto/TSL.cpp
    crypto/X509Crypto.cpp
    util/DateTime.cpp
    XMLDocument.h
)

set_target_properties(digidocpp_util digidocpp_priv PROPERTIES
    COMPILE_DEFINITIONS digidocpp_EXPORTS
    POSITION_INDEPENDENT_CODE YES
)

target_include_directories(digidocpp_priv PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(digidocpp_priv
    digidocpp_util
    ZLIB::ZLIB
    LibXml2::LibXml2
    OpenSSL::SSL
    xmlsec
)

add_library(digidocpp
    ${CMAKE_CURRENT_BINARY_DIR}/digidocpp.conf
    ${SCHEMA_FILES}
    ${PUBLIC_HEADER}
    ${CRYPTO_HEADER}
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
    $<$<PLATFORM_ID:Windows>:crypto/WinSigner.cpp>
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
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER "${PUBLIC_HEADER}"
    RESOURCE ${CMAKE_CURRENT_BINARY_DIR}/digidocpp.conf
    FRAMEWORK_VERSION 1
    FRAMEWORK "${FRAMEWORK}"
    MACOSX_FRAMEWORK_IDENTIFIER "ee.ria.digidocpp"
    MACOSX_FRAMEWORK_SHORT_VERSION_STRING ${PROJECT_VERSION}
    MACOSX_FRAMEWORK_BUNDLE_VERSION ${BUILD_NUMBER}
    MACOSX_RPATH YES
    POSITION_INDEPENDENT_CODE YES
)

target_include_directories(digidocpp PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(digidocpp PRIVATE ${CMAKE_DL_LIBS} minizip digidocpp_priv)

if( BUILD_TOOLS )
    add_executable(digidoc-tool digidoc-tool.cpp)
    target_compile_features(digidoc-tool PUBLIC cxx_std_20)
    target_link_libraries(digidoc-tool digidocpp digidocpp_priv Threads::Threads)
    target_link_options(digidoc-tool PRIVATE
        $<$<PLATFORM_ID:Windows>: /MANIFEST:NO /MANIFEST:EMBED /MANIFESTINPUT:${CMAKE_CURRENT_SOURCE_DIR}/digidoc-tool.manifest>
    )
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
        target_link_libraries(digidoc_java digidocpp digidocpp_util)
        set_target_properties(digidoc_java PROPERTIES
            INSTALL_RPATH $<$<PLATFORM_ID:Darwin>:/Library/Frameworks>
            SWIG_COMPILE_DEFINITIONS $<$<PLATFORM_ID:Windows>:SWIGWIN>
        )
        install(TARGETS digidoc_java DESTINATION $<IF:$<PLATFORM_ID:Darwin>,/Library/Java/Extensions,${CMAKE_INSTALL_LIBDIR}>)
        install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/java/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ee/ria/libdigidocpp FILES_MATCHING PATTERN "*.java")
        if(WIN32)
            install(FILES $<TARGET_PDB_FILE:digidoc_java> DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
        endif()
        if(Java_Development_FOUND)
            file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/glob_java_files.cmake "
            file(GLOB_RECURSE JAVA_COMPILE_FILELISTS \${JAVA_DIR}/*.java)
            file(WRITE \${CMAKE_CURRENT_BINARY_DIR}/java_file_list \"\")
            foreach(JAVA_FILE \${JAVA_COMPILE_FILELISTS})
                file(APPEND \${CMAKE_CURRENT_BINARY_DIR}/java_file_list \"\${JAVA_FILE}\n\")
            endforeach()
            ")
            add_custom_command(TARGET digidoc_java POST_BUILD
                COMMAND ${CMAKE_COMMAND} -D JAVA_DIR=${CMAKE_CURRENT_BINARY_DIR}/java -P ${CMAKE_CURRENT_BINARY_DIR}/glob_java_files.cmake
                BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/java_file_list
            )
            include(UseJava)
            set(CMAKE_JAVA_COMPILE_FLAGS --release 11)
            add_jar(digidocpp_jar SOURCES @${CMAKE_CURRENT_BINARY_DIR}/java_file_list OUTPUT_NAME digidocpp)
            install_jar(digidocpp_jar DESTINATION $<IF:$<PLATFORM_ID:Darwin>,/Library/Java/Extensions,${CMAKE_INSTALL_DATADIR}/digidocpp>)
        endif()
    endif()
    if(Python3_FOUND)
        set(CMAKE_SWIG_FLAGS -py3)
        set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR})
        swig_add_library(digidoc_python LANGUAGE python SOURCES ../libdigidocpp.i)
        target_link_libraries(digidoc_python digidocpp digidocpp_util)
        if(TARGET Python3::SABIModule)
            target_compile_definitions(digidoc_python PRIVATE Py_LIMITED_API=0x03090000)
            target_link_libraries(digidoc_python Python3::SABIModule)
        else()
            target_link_libraries(digidoc_python Python3::Module)
        endif()
        #configure_file(setup.py.cmake setup.py)
        #install(CODE "execute_process(COMMAND python3 ${CMAKE_CURRENT_BINARY_DIR}/setup.py install)")
        if(WIN32)
            set(Python3_SITELIB ${CMAKE_INSTALL_BINDIR})
            install(FILES $<TARGET_PDB_FILE:digidoc_python> DESTINATION ${Python3_SITELIB} OPTIONAL)
        else()
            find_package(Python3 COMPONENTS Interpreter) # for Python3_SITELIB
            set_target_properties(digidoc_python PROPERTIES SUFFIX .so)
        endif()
        set_target_properties(digidoc_python PROPERTIES
            INSTALL_RPATH $<$<PLATFORM_ID:Darwin>:/Library/Frameworks>
            SWIG_COMPILE_DEFINITIONS $<$<PLATFORM_ID:Windows>:SWIGWIN>
        )
        install(TARGETS digidoc_python DESTINATION ${Python3_SITELIB})
        install(FILES ${CMAKE_CURRENT_BINARY_DIR}/digidoc.py DESTINATION ${Python3_SITELIB})
    endif()

    set(CMAKE_SWIG_FLAGS -namespace digidoc)
    set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR}/csharp)
    swig_add_library(digidoc_csharp LANGUAGE csharp SOURCES ../libdigidocpp.i)
    target_link_libraries(digidoc_csharp digidocpp digidocpp_util)
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
    EXPORT libdigidocppExport
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    RESOURCE DESTINATION ${DIGIDOCPP_CONFIG_DIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/digidocpp
    FRAMEWORK DESTINATION ${FRAMEWORK_DESTINATION}
)
if(NOT ANDROID)
    install(EXPORT libdigidocppExport
        FILE libdigidocpp-config.cmake
        NAMESPACE digidocpp::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libdigidocpp
    )
    include(CMakePackageConfigHelpers)
    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/libdigidocpp-config-version.cmake"
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY AnyNewerVersion
    )
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libdigidocpp-config-version.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libdigidocpp
    )
endif()

if(WIN32)
    list(APPEND CRYPTO_HEADER crypto/WinSigner.h)
    target_compile_options(digidocpp_util PUBLIC "/guard:cf")
    target_link_options(digidocpp PUBLIC "/guard:cf")
    target_link_libraries(digidocpp PRIVATE Crypt32 cryptui ncrypt)
    install(FILES $<TARGET_PDB_FILE:digidocpp> $<TARGET_PDB_FILE:digidoc-tool> DESTINATION ${CMAKE_INSTALL_BINDIR} OPTIONAL)
    if(SIGNCERT)
        foreach(TARGET digidocpp digidoc-tool digidoc_java digidoc_csharp digidoc_python)
            if (TARGET ${TARGET})
                if(CROSSSIGNCERT)
                    target_link_options(${TARGET} PRIVATE "/INTEGRITYCHECK")
                endif()
                add_custom_command(TARGET ${TARGET} POST_BUILD
                    COMMAND signtool.exe sign /a /v /s MY /n "${SIGNCERT}" /fd SHA256 /du http://installer.id.ee
                        "$<$<BOOL:${CROSSSIGNCERT}>:/ph;/ac;${CROSSSIGNCERT}>"
                        /tr http://timestamp.digicert.com /td SHA256 $<TARGET_FILE:${TARGET}>
                    COMMAND_EXPAND_LISTS
                )
            endif()
        endforeach()
    endif()
endif()

source_group(Resources FILES ${CMAKE_CURRENT_BINARY_DIR}/digidocpp.conf)
source_group(Resources/schemas FILES ${SCHEMA_FILES})

if( FRAMEWORK )
    install(TARGETS minizip DESTINATION ${CMAKE_INSTALL_LIBDIR}) # for example ios application
    set_source_files_properties( ${SCHEMA_FILES} PROPERTIES MACOSX_PACKAGE_LOCATION Resources/schema )
    set_source_files_properties( ${CRYPTO_HEADER} PROPERTIES MACOSX_PACKAGE_LOCATION Headers/crypto )
    list(GET OPENSSL_LIBRARIES 0 LIBPATH)
    get_filename_component( LIBPATH ${LIBPATH} PATH )
    set(COPY_LIBRARIES_SCRIPT ${CMAKE_BINARY_DIR}/copy_libraries.cmake)
    file(WRITE ${COPY_LIBRARIES_SCRIPT} "
    message(\"Copy dependencies: \$ENV{LIBRARY} \$ENV{BUNDLE_DIR}\")
    file(GET_RUNTIME_DEPENDENCIES LIBRARIES \$ENV{LIBRARY} RESOLVED_DEPENDENCIES_VAR OUT)
    file(COPY \${OUT} DESTINATION \$ENV{BUNDLE_DIR})
    ")
    add_custom_target( embedlibs DEPENDS digidocpp $<TARGET_NAME_IF_EXISTS:digidoc-tool>
        COMMAND mkdir -p $<TARGET_FILE_DIR:digidocpp>/Libraries
        COMMAND ln -s -f Versions/Current/Libraries $<TARGET_BUNDLE_DIR:digidocpp>
        COMMAND ${CMAKE_COMMAND} -E env
            LIBRARY=$<TARGET_FILE:digidocpp>
            BUNDLE_DIR=$<TARGET_BUNDLE_CONTENT_DIR:digidocpp>/Libraries
            ${CMAKE_COMMAND} -P ${COPY_LIBRARIES_SCRIPT}
        COMMAND chmod 644 $<TARGET_FILE_DIR:digidocpp>/Libraries/*
        COMMAND install_name_tool -id 'libcrypto.3.dylib'
            $<TARGET_FILE_DIR:digidocpp>/Libraries/libcrypto.3.dylib
        COMMAND install_name_tool -id 'libssl.3.dylib'
            -change '${LIBPATH}/libcrypto.3.dylib' '@loader_path/libcrypto.3.dylib'
            $<TARGET_FILE_DIR:digidocpp>/Libraries/libssl.3.dylib
        COMMAND install_name_tool -id 'libxmlsec1.1.dylib'
            $<TARGET_FILE_DIR:digidocpp>/Libraries/libxmlsec1.1.dylib
        COMMAND install_name_tool -id 'libxmlsec1-openssl.1.dylib'
            -change '${LIBPATH}/libcrypto.3.dylib' '@loader_path/libcrypto.3.dylib'
            -change '${LIBPATH}/libxmlsec1.1.dylib' '@loader_path/libxmlsec1.1.dylib'
            $<TARGET_FILE_DIR:digidocpp>/Libraries/libxmlsec1-openssl.1.dylib
        COMMAND install_name_tool
            -change '${LIBPATH}/libcrypto.3.dylib' '@loader_path/Libraries/libcrypto.3.dylib'
            -change '${LIBPATH}/libssl.3.dylib' '@loader_path/Libraries/libssl.3.dylib'
            -change '${LIBPATH}/libxmlsec1.1.dylib' '@loader_path/Libraries/libxmlsec1.1.dylib'
            -change '${LIBPATH}/libxmlsec1-openssl.1.dylib' '@loader_path/Libraries/libxmlsec1-openssl.1.dylib'
            $<TARGET_FILE:digidocpp>
    )
    if(BUILD_TOOLS)
        add_custom_command(TARGET digidoc-tool POST_BUILD
            COMMAND cp $<TARGET_FILE:digidoc-tool> $<TARGET_FILE_DIR:digidocpp>/Resources)
        add_custom_command(TARGET embedlibs POST_BUILD
            COMMAND install_name_tool
                -change '${LIBPATH}/libcrypto.3.dylib' '@executable_path/../Libraries/libcrypto.3.dylib'
                -change '${LIBPATH}/libssl.3.dylib' '@executable_path/../Libraries/libssl.3.dylib'
                -change '${LIBPATH}/libxmlsec1.1.dylib' '@executable_path/../Libraries/libxmlsec1.1.dylib'
                -change '${LIBPATH}/libxmlsec1-openssl.1.dylib' '@executable_path/../Libraries/libxmlsec1-openssl.1.dylib'
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
        COMMAND DESTDIR=install ${CMAKE_COMMAND} --install .
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
