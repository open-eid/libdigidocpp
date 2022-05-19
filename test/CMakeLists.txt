find_package( Boost COMPONENTS unit_test_framework )
if( Boost_INCLUDE_DIR )
    set_env(RUN_TESTS "" CACHE STRING "Run tests on build")
    set_env(TEST_FORMAT XML CACHE STRING "Test result format (XML/JUNIT)")
    set( CMAKE_SKIP_RPATH OFF )
    include_directories(${Boost_INCLUDE_DIR})
    add_definitions(
        -DDIGIDOCPPCONF="${CMAKE_SOURCE_DIR}/etc/schema"
        -DPKCS11_MODULE="${PKCS11_MODULE}"
    )
    if( LIBDIGIDOC_FOUND AND LIBDIGIDOC_LINKED )
        add_definitions(-DLINKED_LIBDIGIDOC)
    endif()
    add_executable(unittests libdigidocpp_boost.cpp)
    add_executable(TSLTests TSLTests.cpp)
    target_link_libraries(unittests digidocpp digidocpp_priv)
    target_link_libraries(TSLTests digidocpp digidocpp_util)
    if(WIN32)
        string(REPLACE "/EHsc" "/EHa" CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})
        set_target_properties(unittests TSLTests PROPERTIES COMPILE_FLAGS "/bigobj")
    else()
        set_target_properties(unittests TSLTests PROPERTIES COMPILE_FLAGS "-Wno-unused-parameter -Wno-unused-variable")
    endif()
    if( Boost_VERSION VERSION_LESS 106200 )
        add_test(NAME runtest
            COMMAND ${CMAKE_CURRENT_BINARY_DIR}/unittests --build_info=YES --output_format=XML --log_level=all --report_level=no --log_sink=${CMAKE_CURRENT_BINARY_DIR}/libdigidocpp.xml -- ${CMAKE_CURRENT_SOURCE_DIR}/data
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/src
        )
    else()
        add_test(NAME runtest
            COMMAND ${CMAKE_CURRENT_BINARY_DIR}/unittests  --build_info=YES --report_level=no --logger=${TEST_FORMAT},all,${CMAKE_CURRENT_BINARY_DIR}/libdigidocpp.xml -- ${CMAKE_CURRENT_SOURCE_DIR}/data
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/src
        )
    endif()
    add_test(NAME TSLTest_CA-invalid-type
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/TSLTests -- EE_T-CA-invalid-type.xml bad ${CMAKE_CURRENT_SOURCE_DIR}/data
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/src
    )
    add_test(NAME TSLTest_CA-non-qa
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/TSLTests -- EE_T-CA-non-qa.xml bad ${CMAKE_CURRENT_SOURCE_DIR}/data
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/src
    )
    add_test(NAME TSLTest_CA-withdrawn
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/TSLTests -- EE_T-CA-withdrawn.xml good ${CMAKE_CURRENT_SOURCE_DIR}/data
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/src
    )
    add_test(NAME TSLTest_CA-withdrawn-granted-before
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/TSLTests -- EE_T-CA-withdrawn-granted-before.xml good ${CMAKE_CURRENT_SOURCE_DIR}/data
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/src
    )
    add_test(NAME TSLTest_CA-withdrawn-granted-after
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/TSLTests -- EE_T-CA-withdrawn-granted-after.xml bad ${CMAKE_CURRENT_SOURCE_DIR}/data
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/src
    )
    add_test(NAME TSLTest_OCSP-invalid-type
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/TSLTests -- EE_T-OCSP-invalid-type.xml bad ${CMAKE_CURRENT_SOURCE_DIR}/data
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/src
    )
    add_test(NAME TSLTest_OCSP-withdrawn
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/TSLTests -- EE_T-OCSP-withdrawn.xml bad ${CMAKE_CURRENT_SOURCE_DIR}/data
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/src
    )
    add_test(NAME TSLTest_OCSP-withdrawn-granted-before
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/TSLTests -- EE_T-OCSP-withdrawn-granted-before.xml good ${CMAKE_CURRENT_SOURCE_DIR}/data
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/src
    )
    add_test(NAME TSLTest_OCSP-withdrawn-granted-after
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/TSLTests -- EE_T-OCSP-withdrawn-granted-after.xml bad ${CMAKE_CURRENT_SOURCE_DIR}/data
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/src
    )
    add_test(NAME TSLTest_TSA-invalid-type
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/TSLTests -- EE_T-TSA-invalid-type.xml bad ${CMAKE_CURRENT_SOURCE_DIR}/data
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/src
    )
    add_test(NAME TSLTest_TSA-withdrawn
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/TSLTests -- EE_T-TSA-withdrawn.xml bad ${CMAKE_CURRENT_SOURCE_DIR}/data
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/src
    )
    add_test(NAME TSLTest_TSA-withdrawn-granted-before
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/TSLTests -- EE_T-TSA-withdrawn-granted-before.xml good ${CMAKE_CURRENT_SOURCE_DIR}/data
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/src
    )
    add_test(NAME TSLTest_TSA-withdrawn-granted-after
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/TSLTests -- EE_T-TSA-withdrawn-granted-after.xml bad ${CMAKE_CURRENT_SOURCE_DIR}/data
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/src
    )
    add_test(NAME TSLTest_EE_T-no_QCStatement
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/TSLTests -- EE_T-no_QCStatement.xml bad ${CMAKE_CURRENT_SOURCE_DIR}/data
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/src
    )
    add_test(NAME TSLTest_EE_T-no_QCSD
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/TSLTests -- EE_T-no_QCSD.xml bad ${CMAKE_CURRENT_SOURCE_DIR}/data
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/src
    )
    add_custom_target(check ${RUN_TESTS} COMMAND ${CMAKE_CTEST_COMMAND} DEPENDS unittests TSLTests)
endif()
