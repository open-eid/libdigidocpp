#!/bin/sh
set -e

XERCES_DIR=xerces-c-3.2.0
XMLSEC_DIR=xml-security-c-1.7.3
XSD=xsd-4.0.0-i686-macosx
OPENSSL_DIR=openssl-1.0.2n
#OPENSSL_DIR=openssl-1.1.0g
LIBXML2_DIR=libxml2-2.9.7
ANDROID_NDK=android-ndk-r14b
ARGS="$@"

case "$@" in
*android*)
  case "$@" in
  *x86*)
    ARCH=x86
    ARCH_ABI="x86"
    API=19
    CROSS_COMPILE=i686-linux-android
    ;;
  *arm64*)
    ARCH=arm64
    ARCH_ABI="arm64-v8a"
    API=21
    CROSS_COMPILE=aarch64-linux-android
    export LIBS="-liconv"
    ;;
  *)
    ARCH=arm
    ARCH_ABI="armeabi-v7a"
    API=19
    CROSS_COMPILE=arm-linux-androideabi
    ;;
  esac
  echo "Building for Android ${ARCH} ${API}"

  TARGET_PATH=/Library/libdigidocpp.android${ARCH}
  SYSROOT=${TARGET_PATH}/sysroot
  export PATH=${TARGET_PATH}/bin:${TARGET_PATH}/${CROSS_COMPILE}/bin:$PATH
  export CC=clang
  export CXX=clang++
  export CFLAGS=""
  export CXXFLAGS="${CFLAGS} -Wno-null-conversion"
  CONFIGURE="--host=${CROSS_COMPILE} --enable-static --disable-shared --with-sysroot=${SYSROOT} --disable-dependency-tracking"

  if [ ! -f ${ANDROID_NDK}-darwin-x86_64.zip ]; then
    curl -O https://dl.google.com/android/repository/${ANDROID_NDK}-darwin-x86_64.zip
  fi
  if [ ! -d ${TARGET_PATH} ]; then
    rm -rf ${ANDROID_NDK}
    unzip -qq ${ANDROID_NDK}-darwin-x86_64.zip
    cd ${ANDROID_NDK}
    patch -Np1 -i ../patches/iconv.c.patch
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
  TARGET_PATH=/Library/libdigidocpp.iphoneos
  CONFIGURE="--host=arm-apple-darwin --enable-static --disable-shared --disable-dependency-tracking"
  SYSROOT=$(xcrun -sdk iphoneos --show-sdk-path)
  : ${ARCHS:="armv7 armv7s arm64"}
  : ${IPHONEOS_DEPLOYMENT_TARGET:="9.0"}
  export CFLAGS="-arch ${ARCHS// / -arch } -isysroot ${SYSROOT}"
  export CXXFLAGS="${CFLAGS} -Wno-null-conversion"
  ;;
*simulator*)
  echo "Building for iOS Simulator"
  TARGET_PATH=/Library/libdigidocpp.iphonesimulator
  CONFIGURE="--host=arm-apple-darwin --enable-static --disable-shared --disable-dependency-tracking"
  SYSROOT=$(xcrun -sdk iphonesimulator --show-sdk-path)
  : ${ARCHS:="i386 x86_64"}
  : ${IPHONEOS_DEPLOYMENT_TARGET:="9.0"}
  export CFLAGS="-arch ${ARCHS// / -arch } -isysroot ${SYSROOT}"
  export CXXFLAGS="${CFLAGS} -Wno-null-conversion"
  ;;
*)
  echo "Building for OSX"
  TARGET_PATH=/Library/libdigidocpp
  CONFIGURE="--disable-static --enable-shared --disable-dependency-tracking"
  SYSROOT=$(xcrun -sdk macosx --show-sdk-path)
  : ${ARCHS:="x86_64"}
  : ${MACOSX_DEPLOYMENT_TARGET:="10.11"}
  export CFLAGS=""
  export CXXFLAGS="${CFLAGS} -Wno-null-conversion"
  ;;
esac

function xerces {
    echo Building ${XERCES_DIR}
    if [ ! -f ${XERCES_DIR}.tar.xz ]; then
        curl -O http://www.eu.apache.org/dist/xerces/c/3/sources/${XERCES_DIR}.tar.xz
    fi
    rm -rf ${XERCES_DIR}
    tar xf ${XERCES_DIR}.tar.xz
    cd ${XERCES_DIR}
    sed -ie 's!as_fn_error $? "cannot run test program while cross compiling!$as_echo_n "cannot run test program while cross compiling!' configure
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
      cp ../../patches/xalan-CMakeLists.txt src/CMakeLists.txt
      cmake \
        -DCMAKE_SYSTEM_NAME=Android \
        -DCMAKE_ANDROID_STANDALONE_TOOLCHAIN=${TARGET_PATH} \
        -DCMAKE_ANDROID_ARCH_ABI=${ARCH_ABI} \
        -DCMAKE_INSTALL_PREFIX=${TARGET_PATH} \
        -DCMAKE_BUILD_TYPE="Release" \
        -DXERCESC_INCLUDE_DIR=${TARGET_PATH}/include \
        -DXercesC_LIBRARY_RELEASE=${TARGET_PATH}/lib/libxerces-c.a \
        src
      cp ../../patches/MsgCreator src
      make -s
      sudo make install
      ;;
    *ios*|*simulator*)
      cp ../../patches/xalan-CMakeLists.txt src/CMakeLists.txt
      cmake \
        -DCMAKE_INSTALL_PREFIX=${TARGET_PATH} \
        -DCMAKE_C_COMPILER_WORKS=yes \
        -DCMAKE_CXX_COMPILER_WORKS=yes \
        -DCMAKE_BUILD_TYPE="Release" \
        -DCMAKE_OSX_SYSROOT=${SYSROOT} \
        -DCMAKE_OSX_ARCHITECTURES="${ARCHS// /;}" \
        -DXERCESC_INCLUDE_DIR=${TARGET_PATH}/include \
        -DXercesC_LIBRARY_RELEASE=${TARGET_PATH}/lib/libxerces-c.a \
        src
      cp ../../patches/MsgCreator src
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
    *android*) patch -Np1 -i ../patches/xmlsec.patch ;;
    *) ;;
    esac
    #patch -Np1 -i ../patches/xml-security-c-1.7.3_openssl1.1.patch
    sed -ie 's!as_fn_error $? "cannot run test program while cross compiling!$as_echo_n "cannot run test program while cross compiling!' configure
    ./configure --prefix=${TARGET_PATH} ${CONFIGURE} --with-xerces=${TARGET_PATH} --with-openssl=${TARGET_PATH} --with-xalan=${TARGET_PATH}
    make -s
    sudo make install
    cd ..
}

function libxml2 {
    echo Building ${LIBXML2_DIR}
    case "${ARGS}" in
    *android*) ;;
    *)
      echo "Not needed"
      return 0
      ;;
    esac
    if [ ! -f ${LIBXML2_DIR}.tar.gz ]; then
        curl -O http://xmlsoft.org/sources/${LIBXML2_DIR}.tar.gz
    fi
    rm -rf ${LIBXML2_DIR}
    tar xf ${LIBXML2_DIR}.tar.gz
    cd ${LIBXML2_DIR}
    ./configure --prefix=${TARGET_PATH} ${CONFIGURE} --without-python
    # Android is missing glob.h
    sed -ie 's!runtest$(EXEEXT)!!' Makefile
    sed -ie 's!testrecurse$(EXEEXT)!!' Makefile
    make -s
    sudo make install
    cd ..
}

function xsd {
    echo Building ${XSD}
    if [ ! -f ${XSD}.tar.bz2 ]; then
        curl -O https://www.codesynthesis.com/download/xsd/4.0/macosx/i686/${XSD}.tar.bz2
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
        perl -pi -e 's/-mandroid/-fno-integrated-as/g' Configure
        perl -pi -e 's/.code\t32/#if defined(__thumb2__) || defined(__clang__)\n.syntax unified\n#endif\n#if defined(__thumb2__)\n.thumb\n#else\n.code   32\n#endif/g' crypto/modes/asm/ghash-armv4.pl 
        unset CROSS_COMPILE
        case "${ARGS}" in
        *x86*) ./Configure android-x86 --openssldir=${TARGET_PATH} no-hw no-asm ;;
        *arm64*) ./Configure linux-generic64 --openssldir=${TARGET_PATH} no-hw no-asm -fomit-frame-pointer ;;
        *) ./Configure android-armv7 --openssldir=${TARGET_PATH} no-hw no-asm ;;
        esac
        make -s
        sudo make install_sw
        ;;
    *ios*|*simulator*)
        CRYPTO=""
        SSL=""
        for ARCH in ${ARCHS}
        do
            if [[ "${ARCH}" == "x86_64" ]]; then
                ./Configure darwin64-x86_64-cc --openssldir=${TARGET_PATH} no-hw
                sed -ie 's!^CFLAG=!CFLAG=-isysroot '${SYSROOT}' !' Makefile
            else
                ./Configure iphoneos-cross --openssldir=${TARGET_PATH} no-hw
                sed -ie 's!-isysroot $(CROSS_TOP)/SDKs/$(CROSS_SDK)!-arch '${ARCH}' -isysroot '${SYSROOT}'!' Makefile
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
        KERNEL_BITS=64 ./config --prefix=${TARGET_PATH} shared no-hw enable-ec_nistp_64_gcc_128
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
    echo "  tasks: xerces, xalan, openssl, xmlsec, xsd, all, help"
    echo "To control iOS, macOS builds set environment variables:"
    echo " minimum deployment target"
    echo " - MACOSX_DEPLOYMENT_TARGET=10.11"
    echo " - IPHONEOS_DEPLOYMENT_TARGET=9.0"
    echo " archs to build on iOS"
    echo " - ARCHS=\"armv7 armv7s arm64\" (iOS)"
    echo " - ARCHS=\"i386 x86_64\" (iPhoneSimulator)"
    ;;
esac
