set_env(TEST_FORMAT XML CACHE STRING "Test result format (XML/JUNIT)")
set( CMAKE_SKIP_RPATH OFF )
add_definitions(
    -DDIGIDOCPPCONF="${PROJECT_SOURCE_DIR}/etc/schema"
    -DPKCS11_MODULE="${PKCS11_MODULE}"
    -DSIVA_URL="${SIVA_URL}"
)
add_executable(unittests libdigidocpp_boost.cpp)
add_executable(TSLTests TSLTests.cpp)
target_link_libraries(unittests digidocpp digidocpp_tsl Boost::unit_test_framework)
target_link_libraries(TSLTests digidocpp digidocpp_util Boost::unit_test_framework)
if(WIN32)
    string(REPLACE "/EHsc" "/EHa" CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})
    set_target_properties(unittests TSLTests PROPERTIES COMPILE_FLAGS "/bigobj")
endif()
add_test(NAME runtest
    COMMAND $<TARGET_FILE:unittests> --build_info=YES --report_level=no --logger=${TEST_FORMAT},all,$<TARGET_FILE_DIR:unittests>/libdigidocpp.xml -- ${CMAKE_CURRENT_SOURCE_DIR}/data
    WORKING_DIRECTORY $<TARGET_FILE_DIR:digidocpp>
)

# Bad status tests
foreach(TEST CA-non-qa no_QCStatement no_QCSD
        CA-invalid-type CA-withdrawn CA-granted-later CA-withdrawn-granted-later CA-noqscd-granted-later
        OCSP-invalid-type OCSP-withdrawn OCSP-granted-later OCSP-withdrawn-granted-later OCSP-noqscd-granted-later
        TSA-invalid-type TSA-withdrawn TSA-granted-later TSA-withdrawn-granted-later TSA-noqscd-granted-later
    )
    add_test(NAME TSLTest_${TEST}
        COMMAND $<TARGET_FILE:TSLTests> -- EE_T-${TEST}.xml bad ${CMAKE_CURRENT_SOURCE_DIR}/data
        WORKING_DIRECTORY $<TARGET_FILE_DIR:digidocpp>
    )
endforeach()

# Good status tests
foreach(TEST CA-withdrawn-granted-before CA-noqscd-granted-before
        OCSP-withdrawn-granted-before OCSP-noqscd-granted-before
        TSA-withdrawn-granted-before TSA-noqscd-granted-before
    )
    add_test(NAME TSLTest_${TEST}
        COMMAND $<TARGET_FILE:TSLTests> -- EE_T-${TEST}.xml good ${CMAKE_CURRENT_SOURCE_DIR}/data
        WORKING_DIRECTORY $<TARGET_FILE_DIR:digidocpp>
    )
endforeach()

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} -C $<CONFIG> DEPENDS unittests TSLTests)
