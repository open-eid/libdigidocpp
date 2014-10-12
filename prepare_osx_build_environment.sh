#!/bin/sh

TARGET_PATH=/Library/EstonianIDCard
XERCES_DIR=xerces-c-3.1.1
XMLSEC_DIR=xml-security-c-1.7.2
SDK_PATH=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.9.sdk
export CFLAGS="-isysroot ${SDK_PATH} -mmacosx-version-min=10.7"
export CXXFLAGS="${CFLAGS} -stdlib=libc++"

set -e

function make_xerces {
    curl -C - -O http://www.eu.apache.org/dist/xerces/c/3/sources/${XERCES_DIR}.zip
    unzip ${XERCES_DIR}.zip
    cd $XERCES_DIR
    ./configure --prefix=${TARGET_PATH} --disable-static
    make
    sudo make install
    cd ..
}

function make_xalan {
    curl -C - -O http://www.eu.apache.org/dist/xalan/xalan-c/sources/xalan_c-1.11-src.tar.gz
    tar xf xalan_c-1.11-src.tar.gz
    cd xalan-c-1.11/c
    export XERCESCROOT=${TARGET_PATH}
    export XALANCROOT=${PWD}
    ./runConfigure -p macosx -b 64 -P ${TARGET_PATH}
    make
    sudo XALANCROOT=${PWD} make install
    sudo install_name_tool -id ${TARGET_PATH}/lib/libxalanMsg.111.0.dylib ${TARGET_PATH}/lib/libxalanMsg.dylib
    sudo install_name_tool -id ${TARGET_PATH}/lib/libxalan-c.111.0.dylib ${TARGET_PATH}/lib/libxalan-c.dylib
    sudo install_name_tool -change libxalanMsg.dylib ${TARGET_PATH}/lib/libxalanMsg.111.0.dylib ${TARGET_PATH}/lib/libxalan-c.dylib 
    cd ..
}

function make_xml_security {
    curl -C - -O http://www.eu.apache.org/dist/santuario/c-library/${XMLSEC_DIR}.tar.gz
    tar -vxf ${XMLSEC_DIR}.tar.gz
    cd ${XMLSEC_DIR}
    ./configure --disable-static --prefix=${TARGET_PATH} --with-xerces=${TARGET_PATH} --with-openssl=${SDK_PATH}/usr
# --with-xalan=${TARGET_PATH}
    make
    sudo make install
    cd ..
}

function xsd {
    curl -C - -O http://www.codesynthesis.com/download/xsd/3.3/macosx/i686/xsd-3.3.0-i686-macosx.tar.bz2
    tar -vxf xsd-3.3.0-i686-macosx.tar.bz2
    sudo cp xsd-3.3.0-i686-macosx/bin/xsd ${TARGET_PATH}/bin/
    sudo cp -Rf xsd-3.3.0-i686-macosx/libxsd/xsd ${TARGET_PATH}/include/
}

function check_error {
    if [ "$?" != "0" ]; then
        echo "+++++++++++++++++++++++++++++++++++++++++++++"
        echo "            BUILD FAILED !!!"
        echo "+++++++++++++++++++++++++++++++++++++++++++++"
        exit 1
    fi
}

case "$1" in
 xerces) make_xerces ;;
 xalan) make_xalan ;;
 xmlsec) make_xml_security ;;
 xsd) xsd ;;
 all)
    make_xerces
    check_error
    make_xml_security
    check_error
    xsd
    ;;
 *)
    echo "Usage:"
    echo "  $0 [task]"
    echo "  tasks: xerces, xalan, xmlsec, xsd, all, help"
    ;;
esac
