find_package( Boost COMPONENTS unit_test_framework )
if( Boost_INCLUDE_DIR )
    set( RUN_TESTS $ENV{RUN_TESTS} CACHE STRING "Run tests on build" )
    set( CMAKE_SKIP_RPATH OFF )
    include_directories(
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_BINARY_DIR}/src
        ${XSD_INCLUDE_DIR}
        ${OPENSSL_INCLUDE_DIR}
        ${XERCESC_INCLUDE_DIR}
        ${Boost_INCLUDE_DIR}
    )
    if( LIBDIGIDOC_LINKED )
        list( APPEND unittests_DEFS LINKED_LIBDIGIDOC )
    endif()
	add_executable( unittests libdigidocpp_boost.cpp )
    set_target_properties( unittests PROPERTIES
        COMPILE_DEFINITIONS "DIGIDOCPPCONF=\"${CMAKE_SOURCE_DIR}/etc/schema\";PKCS11_MODULE=\"${PKCS11_MODULE}\";${unittests_DEFS}"
        LINK_LIBRARIES "digidocpp;digidocpp_priv"
    )
    if(WIN32)
        string(REPLACE "/EHsc" "/EHa" CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})
    elseif(APPLE)
        set_source_files_properties( ../src/crypto/PKCS12Signer.cpp PROPERTIES COMPILE_FLAGS "-Wno-deprecated-declarations" )
    endif()
    if(UNIX)
        set_target_properties( unittests PROPERTIES COMPILE_FLAGS "-Wno-unused-parameter -Wno-unused-variable" )
    endif()
    add_custom_target( runtest ${RUN_TESTS}
        COMMAND unittests --build_info=YES --output_format=XML --log_level=all --report_level=no --log_sink=${CMAKE_CURRENT_BINARY_DIR}/libdigidocpp.xml ${CMAKE_CURRENT_SOURCE_DIR}/data
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/src
    )
endif()
