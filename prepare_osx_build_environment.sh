#!/bin/sh
set -e

OPENSSL_DIR=openssl-3.5.6
XMLSEC_DIR=xmlsec1-1.3.10

case "$@" in
*android*|*iphone*|*simulator*)
  echo "vcpkg is used for managing iOS/Android dependencies"
  exit
  ;;
*)
  TARGET_PATH=/Library/libdigidocpp
  : ${ARCHS:="arm64 x86_64"}
  : ${MACOSX_DEPLOYMENT_TARGET:="13.0"}
  export MACOSX_DEPLOYMENT_TARGET
  ;;
esac

function xmlsec {
    echo Building ${XMLSEC_DIR}
    if [ ! -f ${XMLSEC_DIR}.tar.gz ]; then
        XMLSEC_VERSION="${XMLSEC_DIR##*-}"
        curl -O -L https://github.com/lsh123/xmlsec/releases/download/${XMLSEC_VERSION}/${XMLSEC_DIR}.tar.gz
    fi
    rm -rf ${XMLSEC_DIR}
    tar xf ${XMLSEC_DIR}.tar.gz
    cd ${XMLSEC_DIR}
    patch -Np1 -i ../xmlsec1-1.3.10.legacy.patch
    sed -i '' 's/XMLSEC_VERSION_INFO=.*/XMLSEC_VERSION_INFO="1:0:0"/' configure
    ./configure CFLAGS="-arch ${ARCHS// / -arch }" --prefix=${TARGET_PATH} --disable-static --enable-shared \
        --disable-dependency-tracking \
        --disable-crypto-dl \
        --disable-apps-crypto-dl \
        --without-gnutls \
        --without-gcrypt \
        --without-nss \
        --with-openssl=${TARGET_PATH} \
        --disable-apps \
        --disable-docs \
        --disable-mans
    make -s
    sudo make install
    cd -
}

function openssl {
    echo Building ${OPENSSL_DIR}
    if [ ! -f ${OPENSSL_DIR}.tar.gz ]; then
        curl -O -L https://www.openssl.org/source/${OPENSSL_DIR}.tar.gz
    fi
    rm -rf ${OPENSSL_DIR}
    tar xf ${OPENSSL_DIR}.tar.gz
    pushd ${OPENSSL_DIR}
    for ARCH in ${ARCHS}
    do
        ./Configure darwin64-${ARCH} --prefix=${TARGET_PATH} no-apps shared no-module no-tests enable-ec_nistp_64_gcc_128
        make -s > /dev/null
        if [[ ${ARCHS} == ${ARCH}* ]]; then
            sudo make install_sw > /dev/null
        else
            make install_sw DESTDIR=${PWD}/${ARCH} > /dev/null
            mkdir -p universal/${TARGET_PATH}/lib
            pushd ${ARCH}
            for i in $(find ./${TARGET_PATH}/lib -type f -depth 1); do
                lipo -create /$i $i -output ../universal/$i
            done
            popd
            sudo mv universal/${TARGET_PATH}/lib/* ${TARGET_PATH}/lib/
        fi
        make distclean
    done
    popd
}

case "$@" in
*xmlsec*) xmlsec ;;
*openssl*) openssl ;;
*all*)
    openssl
    xmlsec
    ;;
*)
    echo "Usage:"
    echo "  $0 [task]"
    echo "  tasks: openssl, xmlsec, all"
    echo "To control builds set environment variables:"
    echo " - MACOSX_DEPLOYMENT_TARGET=13.0"
    echo " - ARCHS=\"arm64 x86_64\""
    ;;
esac
