# - Find pkcs11
# Find the PKCS11 module
#
# PKCS11_MODULE - pkcs11 module path and name
# PKCS11_FOUND  - True if pkcs11 module found.

if(APPLE)
    find_library(PKCS11_MODULE NAMES opensc-pkcs11.so HINTS /Library/OpenSC/lib)
elseif(WIN32)
    if(NOT PKCS11_MODULE)
        set(PKCS11_MODULE opensc-pkcs11.dll)
    endif()
else()
    if(NOT PKCS11_MODULE)
        set(PKCS11_MODULE opensc-pkcs11.so)
    endif()
endif()

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(PKCS11 DEFAULT_MSG PKCS11_MODULE)
MARK_AS_ADVANCED(PKCS11)
