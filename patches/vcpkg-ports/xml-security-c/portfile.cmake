vcpkg_fail_port_install(MESSAGE "xml-security-c currently only supports Windows X86/X64 platforms" ON_TARGET "OSX" "Linux" ON_ARCH "arm" "arm64")

vcpkg_download_distfile(ARCHIVE
    URLS "https://dlcdn.apache.org/santuario/c-library/xml-security-c-2.0.4.tar.gz"
    FILENAME "xml-security-c-2.0.4.tar.gz"
    SHA512 c2a83b0415ec0a83c932bffb709beac5763e20397f3ec4dfb350a3190de878a860b75482c095b9ac1cae3bbfbcc968b2a26ea912816b0dd4456c7ea0e07f3060
)

vcpkg_extract_source_archive_ex(
    OUT_SOURCE_PATH SOURCE_PATH
    ARCHIVE ${ARCHIVE}
    PATCHES
      001_xml-security-c-2.0.1-win.patch
      002_xml-security-c-SHA3.patch
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
