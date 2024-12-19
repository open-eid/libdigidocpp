#!/bin/sh
set -e

OPENSSL_DIR=openssl-3.0.15
XMLSEC_DIR=xmlsec1-1.3.6
ARGS="$@"

case "$@" in
*android*)
  echo "vcpkg is used for managing android dependencies "
  exit
  ;;
*simulator*)
  echo "Building for iOS Simulator"
  TARGET_PATH=/Library/libdigidocpp.iphonesimulator
  SYSROOT=$(xcrun -sdk iphonesimulator --show-sdk-path)
  : ${ARCHS:="arm64 x86_64"}
  : ${IPHONEOS_DEPLOYMENT_TARGET:="15.0"}
  export IPHONEOS_DEPLOYMENT_TARGET
  export CFLAGS="-arch ${ARCHS// / -arch } -isysroot ${SYSROOT}"
  ;;
*iphonecatalyst*)
  echo "Building for iOS macOS Catalyst"
  TARGET_PATH=/Library/libdigidocpp.iphonecatalyst
  SYSROOT=$(xcrun -sdk macosx --show-sdk-path)
  : ${ARCHS:="arm64 x86_64"}
  : ${IPHONEOS_DEPLOYMENT_TARGET:="15.0"}
  export IPHONEOS_DEPLOYMENT_TARGET
  export CFLAGS="-arch ${ARCHS// / -arch } -target x86_64-apple-ios${IPHONEOS_DEPLOYMENT_TARGET}-macabi -isysroot ${SYSROOT}"
  ;;
*iphoneos*)
  echo "Building for iOS"
  TARGET_PATH=/Library/libdigidocpp.iphoneos
  SYSROOT=$(xcrun -sdk iphoneos --show-sdk-path)
  : ${ARCHS:="arm64"}
  : ${IPHONEOS_DEPLOYMENT_TARGET:="15.0"}
  export IPHONEOS_DEPLOYMENT_TARGET
  export CFLAGS="-arch ${ARCHS// / -arch } -isysroot ${SYSROOT}"
  ;;
*)
  echo "Building for macOS"
  TARGET_PATH=/Library/libdigidocpp
  SYSROOT=$(xcrun -sdk macosx --show-sdk-path)
  : ${ARCHS:="arm64 x86_64"}
  : ${MACOSX_DEPLOYMENT_TARGET:="12.0"}
  export MACOSX_DEPLOYMENT_TARGET
  export CFLAGS="-arch ${ARCHS// / -arch } "
  ;;
esac

function xmlsec {
    echo Building ${XMLSEC_DIR}
    if [ ! -f ${XMLSEC_DIR}.tar.gz ]; then
        curl -O -L http://www.aleksey.com/xmlsec/download/${XMLSEC_DIR}.tar.gz
    fi
    rm -rf ${XMLSEC_DIR}
    tar xf ${XMLSEC_DIR}.tar.gz
    cd ${XMLSEC_DIR}
    patch -Np1 -i ../vcpkg-ports/xmlsec/xmlsec1-1.3.5.legacy.patch
    case "${ARGS}" in
    *iphone*) CONFIGURE="--host=aarch64-apple-darwin --enable-static --disable-shared --without-libxslt" ;;
    *) CONFIGURE="--disable-static --enable-shared" ;;
    esac
    ./configure --prefix=${TARGET_PATH} ${CONFIGURE} \
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
        case "${ARGS}" in
        *simulator*) CC="" CFLAGS="-arch ${ARCH}" ./Configure iossimulator-xcrun --prefix=${TARGET_PATH} no-shared no-dso no-module no-engine no-tests no-ui-console enable-ec_nistp_64_gcc_128 ;;
        *catalyst*) CC="" CFLAGS="-target ${ARCH}-apple-ios${IPHONEOS_DEPLOYMENT_TARGET}-macabi" ./Configure darwin64-${ARCH} --prefix=${TARGET_PATH} no-shared no-dso no-module no-engine no-tests no-ui-console enable-ec_nistp_64_gcc_128 ;;
        *iphone*) CC="" CFLAGS="" ./Configure ios64-xcrun --prefix=${TARGET_PATH} no-shared no-dso no-module no-engine no-tests no-ui-console enable-ec_nistp_64_gcc_128 ;;
        *) CC="" CFLAGS="" ./Configure darwin64-${ARCH} --prefix=${TARGET_PATH} shared no-module no-tests enable-ec_nistp_64_gcc_128
        esac
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
    echo "  $0 [target] [task]"
    echo "  target: macos iphoneos iphonesimulator iphonecatalyst"
    echo "  tasks: openssl, xmlsec, all, help"
    echo "To control builds set environment variables:"
    echo " minimum deployment target"
    echo " - MACOSX_DEPLOYMENT_TARGET=12.0"
    echo " - IPHONEOS_DEPLOYMENT_TARGET=15.0"
    echo " archs to build on macOS/iOS"
    echo " - ARCHS=\"arm64 x86_64\" (macOS)"
    echo " - ARCHS=\"arm64\" (iOS)"
    echo " - ARCHS=\"arm64 x86_64\" (iPhoneSimulator)"
    ;;
esac
