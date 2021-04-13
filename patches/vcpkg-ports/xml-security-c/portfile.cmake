vcpkg_fail_port_install(MESSAGE "xml-security-c currently only supports Windows X86/X64 platforms" ON_TARGET "OSX" "Linux" ON_ARCH "arm" "arm64")

vcpkg_download_distfile(ARCHIVE
    URLS "https://archive.apache.org/dist/santuario/c-library/xml-security-c-2.0.2.tar.gz"
    FILENAME "xml-security-c-2.0.2.tar.gz"
    SHA512 bebadee2daf27181f5bcc955a909397976e8fd2e67f5e546f5adbede0ca790647cbec9181b0b609da59d525ff3baa9f899af2a3d815bc7a2f3a57bd8b30c011b
)

vcpkg_extract_source_archive_ex(
    OUT_SOURCE_PATH SOURCE_PATH
    ARCHIVE ${ARCHIVE}
    PATCHES
      001_xml-security-c-2.0.1-win.patch
)

vcpkg_acquire_msys(MSYS_ROOT PACKAGES sed NO_DEFAULT_PACKAGES)
vcpkg_execute_required_process(
    COMMAND ${MSYS_ROOT}/usr/bin/sed.exe -ie "s!XALAN_USING_XALAN(\\(.*\\))!using xalanc::\\1;!" xsec/*/*.cpp* xsec/*/*.hpp
    WORKING_DIRECTORY ${SOURCE_PATH}
    LOGNAME build-${TARGET_TRIPLET}-sed
)

vcpkg_install_msbuild(
    SOURCE_PATH ${SOURCE_PATH}
    PROJECT_SUBPATH Projects/VC15.0/xsec/xsec_lib/xsec_lib.vcxproj
    OPTIONS /p:UseEnv=True
    OPTIONS_RELEASE /p:OPENSSLROOT=${CURRENT_INSTALLED_DIR} /p:XERCESCROOT=${CURRENT_INSTALLED_DIR} /p:XALANCROOT==${CURRENT_INSTALLED_DIR}
    OPTIONS_DEBUG /p:OPENSSLROOT=${CURRENT_INSTALLED_DIR}/debug /p:XERCESCROOT=${CURRENT_INSTALLED_DIR}/debug /p:XALANCROOT==${CURRENT_INSTALLED_DIR}/debug
    USE_VCPKG_INTEGRATION
)

set(VCPKG_POLICY_EMPTY_INCLUDE_FOLDER enabled)
file(INSTALL ${SOURCE_PATH}/xsec DESTINATION ${CURRENT_PACKAGES_DIR}/include FILES_MATCHING
    PATTERN "*.hpp"
    PATTERN "tools" EXCLUDE
    PATTERN "utils/*utils" EXCLUDE
)
file(INSTALL ${SOURCE_PATH}/LICENSE.txt DESTINATION ${CURRENT_PACKAGES_DIR}/share/xml-security-c RENAME copyright)