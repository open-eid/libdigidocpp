# SPDX-FileCopyrightText: Estonian Information System Authority
# SPDX-License-Identifier: LGPL-2.1-or-later

set( CMAKE_SKIP_RPATH OFF )
add_definitions(
    -DDIGIDOCPPCONF="${PROJECT_SOURCE_DIR}/etc/schema"
    -DPKCS11_MODULE="${PKCS11_MODULE}"
    -DSIVA_URL="${SIVA_URL}"
)
add_executable(unittests libdigidocpp_boost.cpp)
add_executable(TSLTests TSLTests.cpp)
add_executable(X509CertStoreTests X509CertStoreTests.cpp ../src/crypto/X509CertStore.cpp)
target_link_libraries(unittests digidocpp digidocpp_tsl Boost::unit_test_framework)
target_link_libraries(TSLTests digidocpp digidocpp_tsl Boost::unit_test_framework)
target_link_libraries(X509CertStoreTests digidocpp digidocpp_tsl Boost::unit_test_framework ${CMAKE_DL_LIBS})
if(WIN32)
    set_target_properties(unittests TSLTests X509CertStoreTests PROPERTIES COMPILE_FLAGS "/bigobj")
endif()
add_test(NAME unittests
    COMMAND unittests --build_info=YES --report_level=no -- ${CMAKE_CURRENT_SOURCE_DIR}/data
    WORKING_DIRECTORY $<TARGET_FILE_DIR:digidocpp>
)
add_test(NAME X509CertStoreTests
    COMMAND X509CertStoreTests -- ${CMAKE_CURRENT_SOURCE_DIR}/data
    WORKING_DIRECTORY $<TARGET_FILE_DIR:digidocpp>
)

# Bad status tests
foreach(TEST CA-non-qa no_QCStatement no_QCSD
        CA-invalid-type CA-withdrawn CA-granted-later CA-withdrawn-granted-later CA-noqscd-granted-later
        CA-signtime-withdrawn CA-signtime-granted-later CA-signtime-withdrawn-granted-later CA-signtime-noqscd-granted-later
        OCSP-invalid-type OCSP-withdrawn OCSP-granted-later OCSP-withdrawn-granted-later OCSP-noqscd-granted-later
        TSA-invalid-type TSA-withdrawn TSA-granted-later TSA-withdrawn-granted-later TSA-noqscd-granted-later
    )
    add_test(NAME TSLTest_${TEST}
        COMMAND TSLTests -- EE_T-${TEST}.xml bad ${CMAKE_CURRENT_SOURCE_DIR}/data
        WORKING_DIRECTORY $<TARGET_FILE_DIR:digidocpp>
    )
endforeach()

# Good status tests
foreach(TEST CA-withdrawn-granted-before CA-noqscd-granted-before
        CA-signtime-withdrawn-granted-before CA-signtime-noqscd-granted-before
        OCSP-withdrawn-granted-before OCSP-noqscd-granted-before
        TSA-withdrawn-granted-before TSA-noqscd-granted-before
    )
    add_test(NAME TSLTest_${TEST}
        COMMAND TSLTests -- EE_T-${TEST}.xml good ${CMAKE_CURRENT_SOURCE_DIR}/data
        WORKING_DIRECTORY $<TARGET_FILE_DIR:digidocpp>
    )
endforeach()
