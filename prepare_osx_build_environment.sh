#!/bin/sh
set -e

OPENSSL_DIR=openssl-3.0.15
LIBXML2_DIR=libxml2-2.12.9
XMLSEC_DIR=xmlsec1-1.3.5
ANDROID_NDK=android-ndk-r26d
FREETYPE_DIR=freetype-2.10.1
FONTCONFIG_DIR=fontconfig-2.13.1
PODOFO_DIR=podofo-0.9.4
ARGS="$@"

case "$@" in
*android*)
  case "$@" in
  *x86_64*)
    ARCH=x86_64
    ARCH_ABI=x86_64
    CROSS_COMPILE=x86_64-linux-android
    ;;
  *arm64*)
    ARCH=arm64
    ARCH_ABI=arm64-v8a
    CROSS_COMPILE=aarch64-linux-android
    ;;
  *)
    ARCH=arm
    ARCH_ABI=armeabi-v7a
    CROSS_COMPILE=armv7a-linux-androideabi
    ;;
  esac
  echo "Building for Android ${ARCH}"

  : ${ANDROID_NDK_HOME:=$(ls -d /Volumes/${ANDROID_NDK}/AndroidNDK*.app/Contents/NDK)}
  if [ ! -d "${ANDROID_NDK_HOME}" ]; then
    if [ ! -f ${ANDROID_NDK}-darwin.dmg ]; then
      curl -O -L https://dl.google.com/android/repository/${ANDROID_NDK}-darwin.dmg
    fi
    hdiutil attach -mountpoint /Volumes/${ANDROID_NDK} ${ANDROID_NDK}-darwin.dmg
    ANDROID_NDK_HOME=$(ls -d /Volumes/${ANDROID_NDK}/AndroidNDK*.app/Contents/NDK)
  fi

  TARGET_PATH=/Library/libdigidocpp.android${ARCH}
  API=30
  export ANDROID_NDK_HOME
  export ANDROID_NDK_ROOT=${ANDROID_NDK_HOME}
  export PATH=${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH
  export AR=llvm-ar
  export CC=${CROSS_COMPILE}${API}-clang
  export AS=${CC}
  export CXX=${CROSS_COMPILE}${API}-clang++
  export RANLIB=llvm-ranlib
  export STRIP=llvm-strip
  CONFIGURE="--host=${CROSS_COMPILE} --enable-static --disable-shared --disable-dependency-tracking --with-pic"
  ;;
*simulator*)
  echo "Building for iOS Simulator"
  TARGET_PATH=/Library/libdigidocpp.iphonesimulator
  CONFIGURE="--host=aarch64-apple-darwin --enable-static --disable-shared --disable-dependency-tracking"
  SYSROOT=$(xcrun -sdk iphonesimulator --show-sdk-path)
  : ${ARCHS:="arm64 x86_64"}
  : ${IPHONEOS_DEPLOYMENT_TARGET:="15.0"}
  export IPHONEOS_DEPLOYMENT_TARGET
  export CFLAGS="-arch ${ARCHS// / -arch } -isysroot ${SYSROOT}"
  ;;
*iphonecatalyst*)
  echo "Building for iOS macOS Catalyst"
  TARGET_PATH=/Library/libdigidocpp.iphonecatalyst
  CONFIGURE="--host=aarch64-apple-darwin --enable-static --disable-shared --disable-dependency-tracking"
  SYSROOT=$(xcrun -sdk macosx --show-sdk-path)
  : ${ARCHS:="arm64 x86_64"}
  : ${IPHONEOS_DEPLOYMENT_TARGET:="15.0"}
  export IPHONEOS_DEPLOYMENT_TARGET
  export CFLAGS="-arch ${ARCHS// / -arch } -target x86_64-apple-ios${IPHONEOS_DEPLOYMENT_TARGET}-macabi -isysroot ${SYSROOT}"
  ;;
*iphoneos*)
  echo "Building for iOS"
  TARGET_PATH=/Library/libdigidocpp.iphoneos
  CONFIGURE="--host=aarch64-apple-darwin --enable-static --disable-shared --disable-dependency-tracking"
  SYSROOT=$(xcrun -sdk iphoneos --show-sdk-path)
  : ${ARCHS:="arm64"}
  : ${IPHONEOS_DEPLOYMENT_TARGET:="15.0"}
  export IPHONEOS_DEPLOYMENT_TARGET
  export CFLAGS="-arch ${ARCHS// / -arch } -isysroot ${SYSROOT}"
  ;;
*)
  echo "Building for macOS"
  TARGET_PATH=/Library/libdigidocpp
  CONFIGURE="--disable-static --enable-shared --disable-dependency-tracking"
  SYSROOT=$(xcrun -sdk macosx --show-sdk-path)
  : ${ARCHS:="arm64 x86_64"}
  : ${MACOSX_DEPLOYMENT_TARGET:="12.0"}
  export MACOSX_DEPLOYMENT_TARGET
  export CFLAGS="-arch ${ARCHS// / -arch } "
  ;;
esac
export CXXFLAGS="${CFLAGS} -std=gnu++11 -Wno-null-conversion"

function libxml2 {
    echo Building ${LIBXML2_DIR}
    case "${ARGS}" in
    *android*) ;;
    *)
      echo "Not needed"
      return 0
      ;;
    esac
    if [ ! -f ${LIBXML2_DIR}.tar.xz ]; then
        curl -O -L https://download.gnome.org/sources/libxml2/2.12/${LIBXML2_DIR}.tar.xz
    fi
    rm -rf ${LIBXML2_DIR}
    tar xf ${LIBXML2_DIR}.tar.xz
    cd ${LIBXML2_DIR}
    ./configure --prefix=${TARGET_PATH} ${CONFIGURE} --without-python
    # Android is missing glob.h
    sed -ie 's!runtest$(EXEEXT)!!' Makefile
    sed -ie 's!testrecurse$(EXEEXT)!!' Makefile
    make -s
    sudo make install
    cd -
}

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
    *android*) CONF_EXTRA="--without-libxslt --with-libxml=${TARGET_PATH}" ;;
    *iphone*) CONF_EXTRA="--without-libxslt" ;;
    *) ;;
    esac
    ./configure --prefix=${TARGET_PATH} ${CONFIGURE} ${CONF_EXTRA} \
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
    case "${ARGS}" in
    *android*)
        ./Configure android-${ARCH} -D__ANDROID_API__=${API} --prefix=${TARGET_PATH} --openssldir=${TARGET_PATH}/ssl no-shared no-dso no-module no-engine no-tests no-ui-console
        make -s > /dev/null
        sudo make install_sw
        ;;
    *)
        for ARCH in ${ARCHS}
        do
            case "${ARGS}" in
            *simulator*) CC="" CFLAGS="-arch ${ARCH}" ./Configure iossimulator-xcrun --prefix=${TARGET_PATH} no-shared no-dso no-module no-engine no-tests no-ui-console enable-ec_nistp_64_gcc_128 ;;
            *catalyst*) CC="" CFLAGS="-target ${ARCH}-apple-ios-macabi" ./Configure darwin64-${ARCH} --prefix=${TARGET_PATH} no-shared no-dso no-module no-engine no-tests no-ui-console enable-ec_nistp_64_gcc_128 ;;
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
        ;;
    esac
    popd
}

function freetype {
    echo Building ${FREETYPE_DIR}
    if [ ! -f ${FREETYPE_DIR}.tar.bz2 ]; then
        curl -O -L http://download.savannah.gnu.org/releases/freetype/${FREETYPE_DIR}.tar.bz2
    fi
    rm -rf ${FREETYPE_DIR}
    tar xf ${FREETYPE_DIR}.tar.bz2
    cd ${FREETYPE_DIR}
    ./configure --prefix=${TARGET_PATH} ${CONFIGURE} --with-png=no --with-bzip2=no
    make -s
    sudo make install
    cd -
}

function fontconfig {
    echo Building ${FONTCONFIG_DIR}
    if [ ! -f ${FONTCONFIG_DIR}.tar.bz2 ]; then
        curl -O -L https://www.freedesktop.org/software/fontconfig/release//${FONTCONFIG_DIR}.tar.bz2
    fi
    rm -rf ${FONTCONFIG_DIR}
    tar xf ${FONTCONFIG_DIR}.tar.bz2
    cd ${FONTCONFIG_DIR}
    case "${ARGS}" in
    *android*)
      ./configure --prefix=${TARGET_PATH} ${CONFIGURE} --enable-libxml2 \
        FREETYPE_CFLAGS="-I${TARGET_PATH}/include/freetype2" FREETYPE_LIBS="-L${TARGET_PATH}/lib -lfreetype" \
        LIBXML2_CFLAGS="-I${TARGET_PATH}/include/libxml2" LIBXML2_LIBS="-L${TARGET_PATH}/lib -lxml2"
      ;;
    *)
      ./configure --prefix=${TARGET_PATH} ${CONFIGURE} --enable-libxml2 \
        FREETYPE_CFLAGS="-I${TARGET_PATH}/include/freetype2" FREETYPE_LIBS="-L${TARGET_PATH}/lib -lfreetype" \
        LIBXML2_CFLAGS="-I${SYSROOT}/usr/include/libxml2" LIBXML2_LIBS="-L${SYSROOT}/usr/lib -lxml2"
      ;;
    esac
    make -s
    sudo make install
    cd -
}

function podofo {
    echo Building ${PODOFO_DIR}
    if [ ! -f ${PODOFO_DIR}.tar.gz ]; then
        curl -O -L http://downloads.sourceforge.net/project/podofo/podofo/0.9.4/${PODOFO_DIR}.tar.gz
    fi
    rm -rf ${PODOFO_DIR}
    tar xf ${PODOFO_DIR}.tar.gz
    cd ${PODOFO_DIR}
    rm cmake/modules/FindFREETYPE.cmake
    rm cmake/modules/FindOpenSSL.cmake
    rm cmake/modules/FindZLIB.cmake
    sed -ie 's!${PNG_LIBRARIES}!!' CMakeLists.txt
    sed -ie 's!adbe.pkcs7.detached!ETSI.CAdES.detached!' src/doc/PdfSignatureField.cpp 
    PODOFO=""
    for ARCH in ${ARCHS}
    do
        case "${ARGS}" in
        *android*)
            PARAMS="-DCMAKE_SYSTEM_NAME=Android
                    -DCMAKE_ANDROID_STANDALONE_TOOLCHAIN=${TARGET_PATH}
                    -DCMAKE_ANDROID_ARCH_ABI=${ARCH_ABI}
                    -DLIBCRYPTO_LIBRARY_RELEASE=${TARGET_PATH}/lib/libcrypto.a
                    -DPODOFO_BUILD_STATIC=NO
                    -DPODOFO_BUILD_SHARED=YES
                    -DFONTCONFIG_LIBRARIES=${TARGET_PATH}/lib/libfontconfig.a;${TARGET_PATH}/lib/libxml2.a
                    -DZLIB_INCLUDE_DIR=${SYSROOT}/usr/include
                    -DZLIB_LIBRARY=${SYSROOT}/usr/lib/libz.so"
            ;;
        *iphone*)
            PARAMS="-DLIBCRYPTO_LIBRARY_RELEASE=${TARGET_PATH}/lib/libcrypto.a
                    -DPODOFO_BUILD_STATIC=YES
                    -DPODOFO_BUILD_SHARED=NO
                    -DCMAKE_OSX_SYSROOT=${SYSROOT}
                    -DCMAKE_OSX_ARCHITECTURES=${ARCH}"
            ;;
        *)
            PARAMS="-DLIBCRYPTO_LIBRARY_RELEASE=${TARGET_PATH}/lib/libcrypto.dylib
                    -DPODOFO_BUILD_STATIC=YES
                    -DPODOFO_BUILD_SHARED=NO
                    -DCMAKE_OSX_SYSROOT=${SYSROOT}
                    -DCMAKE_OSX_ARCHITECTURES=${ARCH}"
            ;;
        esac
        cmake \
            -DCMAKE_INSTALL_PREFIX=${TARGET_PATH} \
            -DCMAKE_C_COMPILER_WORKS=yes \
            -DCMAKE_CXX_COMPILER_WORKS=yes \
            -DCMAKE_C_FLAGS="${SDK_CFLAGS}" \
            -DCMAKE_CXX_FLAGS="${SDK_CFLAGS} -I${TARGET_PATH}/include/freetype2" \
            -DCMAKE_BUILD_TYPE="Release" \
            -DPODOFO_BUILD_LIB_ONLY=YES \
            -DOPENSSL_ROOT_DIR=${TARGET_PATH} \
            -DLIBCRYPTO_INCLUDE_DIR=${TARGET_PATH}/include \
            -DPNG_PNG_INCLUDE_DIR=PNG_PNG_INCLUDE_DIR-NOTFOUND \
            -DPNG_LIBRARY_RELEASE=PNG_LIBRARY_RELEASE-NOTFOUND \
            -DLIBJPEG_LIBRARY_RELEASE=LIBJPEG_LIBRARY_RELEASE-NOTFOUND \
            -DTIFF_INCLUDE_DIR=TIFF_INCLUDE_DIR-NOTFOUND \
            -DTIFF_LIBRARY_RELEASE=TIFF_LIBRARY_RELEASE-NOTFOUND \
            ${PARAMS} .
        make -s
        make install DESTDIR=${ARCH}
        PODOFO="${PODOFO} ${ARCH}/${TARGET_PATH}/lib/libpodofo.a"
    done
    sudo make install
    tmp=(${ARCHS})
    if [ "${#tmp[@]}" -ne "1" ]; then
        echo lipo
        sudo lipo -create ${PODOFO} -output ${TARGET_PATH}/lib/libpodofo.a
    fi
    cd -
}

case "$@" in
*libxml2*) libxml2 ;;
*xmlsec*) xmlsec ;;
*openssl*) openssl ;;
*freetype*) freetype ;;
*fontconfig*) fontconfig ;;
*podofo*) podofo ;;
*all*)
    openssl
    libxml2
    xmlsec
    ;;
*)
    echo "Usage:"
    echo "  $0 [target] [task]"
    echo "  target: osx iphoneos iphonesimulator iphonecatalyst androidarm androidarm64 androidx86_64"
    echo "  tasks: openssl, libxml2, xmlsec, all, help"
    echo "To control iOS, macOS builds set environment variables:"
    echo " minimum deployment target"
    echo " - MACOSX_DEPLOYMENT_TARGET=12.0"
    echo " - IPHONEOS_DEPLOYMENT_TARGET=15.0"
    echo " archs to build on macOS/iOS"
    echo " - ARCHS=\"arm64 x86_64\" (macOS)"
    echo " - ARCHS=\"arm64\" (iOS)"
    echo " - ARCHS=\"arm64 x86_64\" (iPhoneSimulator)"
    ;;
esac
