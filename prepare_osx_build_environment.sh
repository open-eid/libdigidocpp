#!/bin/sh

XERCES_DIR=xerces-c-3.1.4
XMLSEC_DIR=xml-security-c-1.7.2
XSD=xsd-4.0.0-i686-macosx
OPENSSL_DIR=openssl-1.0.2h
LIBXML2_DIR=libxml2-2.9.3
ARGS="$@"

case "$@" in
*android*)
  echo "Building for Android"

  if [ ! -f android-ndk-r10e-darwin-x86_64.bin ]; then
    curl -O http://dl.google.com/android/ndk/android-ndk-r10e-darwin-x86_64.bin
  fi
  rm -rf android-ndk-r10e
  chmod +x android-ndk-r10e-darwin-x86_64.bin;
  ./android-ndk-r10e-darwin-x86_64.bin | egrep -v ^Extracting;

  case "$@" in
  *x86*)
    ARCH=x86
    TOOLCHAIN=x86-4.9
    CROSS_COMPILE=i686-linux-android
    ;;
  *)
    ARCH=arm
    TOOLCHAIN=arm-linux-androideabi-4.9
    CROSS_COMPILE=arm-linux-androideabi
    ;;
  esac

  TARGET_PATH=/Library/EstonianIDCard.android${ARCH}
  export ANDROID_NDK=$PWD/android-ndk-r10e
  export SYSROOT=${TARGET_PATH}/sysroot
  export ANDROID_PREFIX=${TARGET_PATH}/${CROSS_COMPILE}
  export ANDROID_DEV=${SYSROOT}/usr
  export PATH=${TARGET_PATH}/bin:${ANDROID_PREFIX}/bin:$PATH
  export CC=${CROSS_COMPILE}-gcc
  export CXX=${CROSS_COMPILE}-g++
  export CFLAGS="-I${TARGET_PATH}/include --sysroot=${SYSROOT} -I${SYSROOT}/usr/include -I${ANDROID_PREFIX}/include"
  export CXXFLAGS="${CFLAGS}"
  export LDFLAGS="-L${TARGET_PATH}/lib -L${SYSROOT}/usr/lib -L${ANDROID_PREFIX}/lib"
  export LIBS="-liconv -lsupc++ -lstdc++ -lgnustl_shared -lglob -lz"

  sudo ${ANDROID_NDK}/build/tools/make-standalone-toolchain.sh \
    --toolchain=${TOOLCHAIN} --platform=android-19 --install-dir=${TARGET_PATH}

  #iconv for xerces
  sudo cp ${ANDROID_NDK}/sources/android/support/include/iconv.h ${TARGET_PATH}/include/
  patch -Np0 -i examples/libdigidocpp-android/iconv.c.patch
  sudo ${CC} ${CFLAGS} -std=c99 -o ${TARGET_PATH}/lib/libiconv.o -c ${ANDROID_NDK}/sources/android/support/src/musl-locale/iconv.c
  sudo ${CROSS_COMPILE}-ar rcs ${TARGET_PATH}/lib/libiconv.a ${TARGET_PATH}/lib/libiconv.o

  #glob for xml-security-c
  sudo ln -s ${ANDROID_DEV}/include/sys/types.h ${ANDROID_DEV}/include/sys/_types.h
  curl -O https://raw.githubusercontent.com/white-gecko/TokyoCabinet/master/glob.c
  curl -O https://raw.githubusercontent.com/white-gecko/TokyoCabinet/master/glob.h
  sudo cp glob.h ${TARGET_PATH}/include/
  sudo ${CC} ${CFLAGS} -std=c99 -o ${TARGET_PATH}/lib/libglob.o -c glob.c
  sudo ${CROSS_COMPILE}-ar rcs ${TARGET_PATH}/lib/libglob.a ${TARGET_PATH}/lib/libglob.o

  CONFIGURE="--host=${ARCH} --enable-static --disable-shared --with-sysroot=${SYSROOT}"
  ;;
*ios*)
  echo "Building for iOS"
  TARGET_PATH=/Library/EstonianIDCard.iphoneos
  CONFIGURE="--host=arm-apple-darwin --enable-static --disable-shared"
  export SDK_PATH=$(xcrun -sdk iphoneos --show-sdk-path)
  export CFLAGS="-arch armv7 -arch armv7s -arch arm64 -miphoneos-version-min=8.0 -isysroot ${SDK_PATH} -Wno-null-conversion"
  export CXXFLAGS="${CFLAGS} -stdlib=libc++"
  ARCHS="armv7 armv7s arm64"
  ;;
*simulator*)
  echo "Building for iOS Simulator"
  TARGET_PATH=/Library/EstonianIDCard.iphonesimulator
  CONFIGURE="--host=arm-apple-darwin --enable-static --disable-shared"
  export SDK_PATH=$(xcrun -sdk iphonesimulator --show-sdk-path)
  export CFLAGS="-arch i386 -arch x86_64 -miphoneos-version-min=8.0 -isysroot ${SDK_PATH} -Wno-null-conversion"
  export CXXFLAGS="${CFLAGS} -stdlib=libc++"
  ARCHS="i386 x86_64"
  ;;
*)
  echo "Building for OSX"
  XMLSEC_DIR=xml-security-c-1.7.3
  TARGET_PATH=/Library/EstonianIDCard
  CONFIGURE="--disable-static"
  export SDK_PATH=$(xcrun -sdk macosx --show-sdk-path)
  export CFLAGS="-mmacosx-version-min=10.7 -Wno-null-conversion"
  export CXXFLAGS="${CFLAGS} -stdlib=libc++"
  ;;
esac

set -e

function xerces {
    if [ ! -f ${XERCES_DIR}.zip ]; then
        curl -O http://www.eu.apache.org/dist/xerces/c/3/sources/${XERCES_DIR}.zip
    fi
    rm -rf ${XERCES_DIR}
    unzip -qq ${XERCES_DIR}.zip
    cd ${XERCES_DIR}
    case "${ARGS}" in
    *android*) patch -Np1 -i ../examples/libdigidocpp-android/XMLAbstractDoubleFloat.cpp.patch ;;
    *) ;;
    esac
    ./configure --prefix=${TARGET_PATH} ${CONFIGURE}
    make -s
    sudo make install
    cd ..
}

function xalan {
    if [ ! -f xalan_c-1.11-src.tar.gz ]; then
        curl -O http://www.eu.apache.org/dist/xalan/xalan-c/sources/xalan_c-1.11-src.tar.gz
    fi
    rm -rf xalan-c-1.11
    tar xf xalan_c-1.11-src.tar.gz
    cd xalan-c-1.11/c
    export XERCESCROOT=${TARGET_PATH}
    export XALANCROOT=${PWD}
    export LDFLAGS="-headerpad_max_install_names"
    ./runConfigure -p macosx -b 64 -P ${TARGET_PATH}
    make -s
    sudo XALANCROOT=${PWD} make install
    sudo install_name_tool -id ${TARGET_PATH}/lib/libxalanMsg.111.0.dylib ${TARGET_PATH}/lib/libxalanMsg.dylib
    sudo install_name_tool -id ${TARGET_PATH}/lib/libxalan-c.111.0.dylib ${TARGET_PATH}/lib/libxalan-c.dylib
    sudo install_name_tool -change libxalanMsg.dylib ${TARGET_PATH}/lib/libxalanMsg.111.0.dylib ${TARGET_PATH}/lib/libxalan-c.dylib 
    cd ../..
}

function xml_security {
    if [ ! -f ${XMLSEC_DIR}.tar.gz ]; then
        curl -O http://www.eu.apache.org/dist/santuario/c-library/${XMLSEC_DIR}.tar.gz
    fi
    rm -rf ${XMLSEC_DIR}
    tar xf ${XMLSEC_DIR}.tar.gz
    cd ${XMLSEC_DIR}
    ./configure --prefix=${TARGET_PATH} ${CONFIGURE} --with-xerces=${TARGET_PATH} --with-openssl=${TARGET_PATH} --with-xalan=${TARGET_PATH}
    make -s
    sudo make install
    cd ..
}

function libxml2 {
    if [ ! -f ${LIBXML2_DIR}.tar.gz ]; then
        curl -O http://xmlsoft.org/sources/${LIBXML2_DIR}.tar.gz
    fi
    rm -rf ${LIBXML2_DIR}
    tar xf ${LIBXML2_DIR}.tar.gz
    cd ${LIBXML2_DIR}
    ./configure --prefix=${TARGET_PATH} ${CONFIGURE} --without-python
    make -s
    sudo make install
    cd ..
}

function xsd {
    if [ ! -f ${XSD}.tar.bz2 ]; then
        curl -O http://www.codesynthesis.com/download/xsd/4.0/macosx/i686/${XSD}.tar.bz2
    fi
    rm -rf ${XSD}
    tar xf ${XSD}.tar.bz2
    sudo mkdir -p ${TARGET_PATH}/bin ${TARGET_PATH}/include
    sudo cp ${XSD}/bin/xsd ${TARGET_PATH}/bin/
    sudo cp -Rf ${XSD}/libxsd/xsd ${TARGET_PATH}/include/
}

function openssl {
    if [ ! -f ${OPENSSL_DIR}.tar.gz ]; then
        curl -O https://www.openssl.org/source/${OPENSSL_DIR}.tar.gz
    fi
    rm -rf ${OPENSSL_DIR}
    tar xf ${OPENSSL_DIR}.tar.gz
    cd ${OPENSSL_DIR}

    case "${ARGS}" in
    *android*)
        unset CROSS_COMPILE
        case "${ARGS}" in
        *x86*) ./Configure android-x86 --openssldir=${TARGET_PATH} ;;
        *) ./Configure android-armv7 --openssldir=${TARGET_PATH} ;;
        esac
        make -s
        sudo make install
        ;;
    *ios*|*simulator*)
        CRYPTO=""
        SSL=""
        for ARCH in $ARCHS
        do
            export ARCH
            if [[ "${ARCH}" == "x86_64" ]]; then
                ./Configure darwin64-x86_64-cc --openssldir=${TARGET_PATH}
                sed -ie 's!^CFLAG=!CFLAG=-isysroot ${SDK_PATH} -miphoneos-version-min=8.0 !' Makefile
            else
                ./Configure iphoneos-cross --openssldir=${TARGET_PATH}
                sed -ie 's!-isysroot $(CROSS_TOP)/SDKs/$(CROSS_SDK)!-arch ${ARCH} -isysroot ${SDK_PATH} -miphoneos-version-min=8.0!' Makefile
            fi
            make -s install INSTALL_PREFIX=${PWD}/${ARCH}
            make clean
            sudo cp -R ${ARCH}/${TARGET_PATH}/include/openssl ${TARGET_PATH}/include
            CRYPTO="${CRYPTO} ${ARCH}/${TARGET_PATH}/lib/libcrypto.a"
            SSL="${SSL} ${ARCH}/${TARGET_PATH}/lib/libssl.a"
        done
        sudo lipo -create ${CRYPTO} -output ${TARGET_PATH}/lib/libcrypto.a
        sudo lipo -create ${SSL} -output ${TARGET_PATH}/lib/libssl.a
        ;;
    *)
        KERNEL_BITS=64 ./config --prefix=${TARGET_PATH} shared
        sed -ie 's!^CFLAG=!CFLAG=${CFLAGS} !' Makefile
        make -s
        sudo make install
        ;;
    esac

    cd ..
}

case "$@" in
*xerces*) xerces ;;
*xalan*) xalan ;;
*xmlsec*) xml_security ;;
*libxml2*) libxml2 ;;
*xsd*) xsd ;;
*openssl*) openssl ;;
*all*)
    xerces
    openssl
    case "$@" in
    *ios*|*simulator*|*android*) ;;
    *) xalan ;;
    esac
    xml_security
    xsd
    ;;
*)
    echo "Usage:"
    echo "  $0 [target] [host] [task]"
    echo "  target: osx ios simulator android"
    echo "  host: arm x86"
    echo "  tasks: xerces, xalan, xmlsec, xsd, all, help"
    ;;
esac
