#!/bin/sh
set -e

XERCES_DIR=xerces-c-3.1.4
XMLSEC_DIR=xml-security-c-1.7.3
XSD=xsd-4.0.0-i686-macosx
OPENSSL_DIR=openssl-1.0.2k
LIBXML2_DIR=libxml2-2.9.4
ANDROID_NDK=android-ndk-r14
ARGS="$@"

case "$@" in
*android*)
  case "$@" in
  *x86*)
    ARCH=x86
    API=19
    CROSS_COMPILE=i686-linux-android
    ;;
  *arm64*)
    ARCH=arm64
    API=21
    CROSS_COMPILE=aarch64-linux-android
    export LIBS="-liconv"
    ;;
  *)
    ARCH=arm
    API=19
    CROSS_COMPILE=arm-linux-androideabi
    ;;
  esac
  echo "Building for Android ${ARCH} ${API}"

  TARGET_PATH=/Library/EstonianIDCard.android${ARCH}
  SYSROOT=${TARGET_PATH}/sysroot
  export PATH=${TARGET_PATH}/bin:${TARGET_PATH}/${CROSS_COMPILE}/bin:$PATH
  export CC=clang
  export CXX=clang++
  export CFLAGS=""
  export CXXFLAGS="${CFLAGS} -Wno-null-conversion"
  CONFIGURE="--host=${CROSS_COMPILE} --disable-static --enable-shared --with-sysroot=${SYSROOT} --disable-dependency-tracking"

  if [ ! -f ${ANDROID_NDK}-darwin-x86_64.zip ]; then
    curl -O https://dl.google.com/android/repository/${ANDROID_NDK}-darwin-x86_64.zip
  fi
  if [ ! -d ${TARGET_PATH} ]; then
    rm -rf ${ANDROID_NDK}
    unzip -qq ${ANDROID_NDK}-darwin-x86_64.zip
    cd ${ANDROID_NDK}
    patch -Np1 -i ../examples/libdigidocpp-android/iconv.c.patch
    sudo ./build/tools/make_standalone_toolchain.py \
      --arch=${ARCH} --api=${API} --stl=libc++ --install-dir=${TARGET_PATH}

    #iconv for xerces
    sudo cp sources/android/support/include/iconv.h ${SYSROOT}/usr/include/
    sudo ${CROSS_COMPILE}-gcc -I${SYSROOT}/usr/include -std=c99 -o ${SYSROOT}/usr/lib/libiconv.o -c sources/android/support/src/musl-locale/iconv.c
    sudo ${CROSS_COMPILE}-ar rcs ${SYSROOT}/usr/lib/libiconv.a ${SYSROOT}/usr/lib/libiconv.o
    cd ..
  fi
  ;;
*ios*)
  echo "Building for iOS"
  TARGET_PATH=/Library/EstonianIDCard.iphoneos
  CONFIGURE="--host=arm-apple-darwin --enable-static --disable-shared --disable-dependency-tracking"
  SYSROOT=$(xcrun -sdk iphoneos --show-sdk-path)
  SDK_CFLAGS="-miphoneos-version-min=9.0"
  export CFLAGS="-arch armv7 -arch armv7s -arch arm64 ${SDK_CFLAGS} -isysroot ${SYSROOT}"
  export CXXFLAGS="${CFLAGS} -Wno-null-conversion"
  ARCHS="armv7 armv7s arm64"
  ;;
*simulator*)
  echo "Building for iOS Simulator"
  TARGET_PATH=/Library/EstonianIDCard.iphonesimulator
  CONFIGURE="--host=arm-apple-darwin --enable-static --disable-shared --disable-dependency-tracking"
  SYSROOT=$(xcrun -sdk iphonesimulator --show-sdk-path)
  SDK_CFLAGS="-miphoneos-version-min=9.0"
  export CFLAGS="-arch i386 -arch x86_64 ${SDK_CFLAGS} -isysroot ${SYSROOT}"
  export CXXFLAGS="${CFLAGS} -Wno-null-conversion"
  ARCHS="i386 x86_64"
  ;;
*)
  echo "Building for OSX"
  TARGET_PATH=/Library/EstonianIDCard
  CONFIGURE="--disable-static --disable-dependency-tracking"
  SYSROOT=$(xcrun -sdk macosx --show-sdk-path)
  SDK_CFLAGS="-mmacosx-version-min=10.9"
  export CFLAGS="${SDK_CFLAGS}"
  export CXXFLAGS="${CFLAGS} -Wno-null-conversion"
  ARCHS="x86_64"
  ;;
esac

function xerces {
    echo Building ${XERCES_DIR}
    if [ ! -f ${XERCES_DIR}.zip ]; then
        curl -O http://www.eu.apache.org/dist/xerces/c/3/sources/${XERCES_DIR}.zip
    fi
    rm -rf ${XERCES_DIR}
    unzip -qq ${XERCES_DIR}.zip
    cd ${XERCES_DIR}
    ./configure --prefix=${TARGET_PATH} ${CONFIGURE}
    make -s
    sudo make install
    cd ..
}

function xalan {
    echo Building xalan-c-1.11
    if [ ! -f xalan_c-1.11-src.tar.gz ]; then
        curl -O http://www.eu.apache.org/dist/xalan/xalan-c/sources/xalan_c-1.11-src.tar.gz
    fi
    rm -rf xalan-c-1.11
    tar xf xalan_c-1.11-src.tar.gz
    cd xalan-c-1.11/c
    export XERCESCROOT=${TARGET_PATH}
    export XALANCROOT=${PWD}
    case "${ARGS}" in
    *android*)
      patch -Np2 -i ../../examples/libdigidocpp-android/xalan-android.patch
      mkdir bin
      cp ../../examples/libdigidocpp-android/MsgCreator bin
      ./runConfigure -p linux -P ${TARGET_PATH} -c ${CC} -x ${CXX} -r none -C --host=arm-unknown-linux
      make -s
      sudo XALANCROOT=${PWD} make install
      ;;
    *ios*|*simulator*)
      cp ../../examples/libdigidocpp-ios/xalan-CMakeLists.txt src/CMakeLists.txt
      cmake \
        -DCMAKE_INSTALL_PREFIX=${TARGET_PATH} \
        -DCMAKE_C_COMPILER_WORKS=yes \
        -DCMAKE_CXX_COMPILER_WORKS=yes \
        -DCMAKE_C_FLAGS="${SDK_CFLAGS}" \
        -DCMAKE_CXX_FLAGS="${SDK_CFLAGS}" \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_OSX_SYSROOT=${SYSROOT} \
        -DCMAKE_OSX_ARCHITECTURES="${ARCHS// /;}" \
        -DXERCESC_INCLUDE_DIR=${TARGET_PATH}/include \
        -DXercesC_LIBRARY_RELEASE=${TARGET_PATH}/lib/libxerces-c.a \
        src
      cp ../../examples/libdigidocpp-android/MsgCreator src
      make -s
      sudo make install
      ;;
    *)
      export LDFLAGS="-headerpad_max_install_names"
      ./runConfigure -p macosx -b 64 -P ${TARGET_PATH}
      make -s
      sudo XALANCROOT=${PWD} make install
      sudo install_name_tool -id ${TARGET_PATH}/lib/libxalanMsg.111.0.dylib ${TARGET_PATH}/lib/libxalanMsg.dylib
      sudo install_name_tool -id ${TARGET_PATH}/lib/libxalan-c.111.0.dylib ${TARGET_PATH}/lib/libxalan-c.dylib
      sudo install_name_tool -change libxalanMsg.dylib ${TARGET_PATH}/lib/libxalanMsg.111.0.dylib ${TARGET_PATH}/lib/libxalan-c.dylib
      ;;
    esac
    cd ../..
}

function xml_security {
    echo Building ${XMLSEC_DIR}
    if [ ! -f ${XMLSEC_DIR}.tar.gz ]; then
        curl -O http://www.eu.apache.org/dist/santuario/c-library/${XMLSEC_DIR}.tar.gz
    fi
    rm -rf ${XMLSEC_DIR}
    tar xf ${XMLSEC_DIR}.tar.gz
    cd ${XMLSEC_DIR}
    case "${ARGS}" in
    *android*) patch -Np1 -i ../examples/libdigidocpp-android/xmlsec.patch ;;
    *) ;;
    esac
    sed -ie 's!as_fn_error $? "cannot run test program while cross compiling!$as_echo_n "cannot run test program while cross compiling!' configure
    ./configure --prefix=${TARGET_PATH} ${CONFIGURE} --with-xerces=${TARGET_PATH} --with-openssl=${TARGET_PATH} --with-xalan=${TARGET_PATH}
    make -s
    sudo make install
    cd ..
}

function libxml2 {
    echo Building ${LIBXML2_DIR}
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
    echo Building ${XSD}
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
    echo Building ${OPENSSL_DIR}
    if [ ! -f ${OPENSSL_DIR}.tar.gz ]; then
        curl -O https://www.openssl.org/source/${OPENSSL_DIR}.tar.gz
    fi
    rm -rf ${OPENSSL_DIR}
    tar xf ${OPENSSL_DIR}.tar.gz
    cd ${OPENSSL_DIR}

    case "${ARGS}" in
    *android*)
        CCOLD=${CC}
        export CC=${CROSS_COMPILE}-gcc
        unset CROSS_COMPILE
        case "${ARGS}" in
        *x86*) ./Configure android-x86 --openssldir=${TARGET_PATH} no-apps no-hw no-engines ;;
        *arm64*)
          ./Configure linux-generic64 --openssldir=${TARGET_PATH} no-apps no-hw no-engines no-shared -DB_ENDIAN  \
             -fPIC -DOPENSSL_PIC -DDSO_DLFCN -DHAVE_DLFCN_H -mandroid -O3 -fomit-frame-pointer -Wall
          ;;
        *) ./Configure android-armv7 --openssldir=${TARGET_PATH} no-apps no-hw no-engines ;;
        esac
        make -s
        sudo make install_sw
        export CC=${CCOLD}
        ;;
    *ios*|*simulator*)
        CRYPTO=""
        SSL=""
        for ARCH in ${ARCHS}
        do
            if [[ "${ARCH}" == "x86_64" ]]; then
                ./Configure darwin64-x86_64-cc --openssldir=${TARGET_PATH} no-apps no-hw no-engines
                sed -ie 's!^CFLAG=!CFLAG=-isysroot '${SYSROOT}' '${SDK_CFLAGS}' !' Makefile
            else
                ./Configure iphoneos-cross --openssldir=${TARGET_PATH} no-apps no-hw no-engines
                sed -ie 's!-isysroot $(CROSS_TOP)/SDKs/$(CROSS_SDK)!-arch '${ARCH}' -isysroot '${SYSROOT}' '${SDK_CFLAGS}'!' Makefile
            fi
            make -s depend all install_sw INSTALL_PREFIX=${PWD}/${ARCH} > /dev/null
            make clean
            sudo cp -R ${ARCH}/${TARGET_PATH}/include/openssl ${TARGET_PATH}/include
            CRYPTO="${CRYPTO} ${ARCH}/${TARGET_PATH}/lib/libcrypto.a"
            SSL="${SSL} ${ARCH}/${TARGET_PATH}/lib/libssl.a"
        done
        sudo lipo -create ${CRYPTO} -output ${TARGET_PATH}/lib/libcrypto.a
        sudo lipo -create ${SSL} -output ${TARGET_PATH}/lib/libssl.a
        ;;
    *)
        KERNEL_BITS=64 ./config --prefix=${TARGET_PATH} shared no-apps no-hw no-engines enable-ec_nistp_64_gcc_128
        sed -ie 's!^CFLAG=!CFLAG='${SDK_CFLAGS}' !' Makefile
        make -s
        sudo make install_sw
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
    xalan
    xml_security
    xsd
    ;;
*)
    echo "Usage:"
    echo "  $0 [target] [task]"
    echo "  target: osx ios simulator androidarm androidarm64 androidx86"
    echo "  tasks: xerces, xalan, xmlsec, xsd, all, help"
    ;;
esac
