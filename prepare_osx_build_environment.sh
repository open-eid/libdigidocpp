#!/bin/sh
set -e

XERCES_DIR=xerces-c-3.2.3
XALAN_DIR=xalan_c-1.12
XMLSEC_DIR=xml-security-c-2.0.4
XSD=xsd-4.0.0-i686-macosx
OPENSSL_DIR=openssl-1.1.1m
LIBXML2_DIR=libxml2-2.9.10
ANDROID_NDK=android-ndk-r23b
FREETYPE_DIR=freetype-2.10.1
FONTCONFIG_DIR=fontconfig-2.13.1
PODOFO_DIR=podofo-0.9.4
ARGS="$@"

case "$@" in
*android*)
  case "$@" in
  *x86_64*)
    ARCH=x86_64
    ARCH_ABI="x86_64"
    CROSS_COMPILE=x86_64-linux-android
    ;;
  *x86*)
    ARCH=x86
    ARCH_ABI="x86"
    CROSS_COMPILE=i686-linux-android
    ;;
  *arm64*)
    ARCH=arm64
    ARCH_ABI="arm64-v8a"
    CROSS_COMPILE=aarch64-linux-android
    ;;
  *)
    ARCH=arm
    ARCH_ABI="armeabi-v7a"
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
  fi

  TARGET_PATH=/Library/libdigidocpp.android${ARCH}
  ABI=21
  export ANDROID_NDK_HOME
  export PATH=${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH
  export AR=llvm-ar
  export CC=${CROSS_COMPILE}${ABI}-clang
  export AS=${CC}
  export CXX=${CROSS_COMPILE}${ABI}-clang++
  export RANLIB=llvm-ranlib
  export STRIP=llvm-strip
  export CFLAGS="-I${TARGET_PATH}/include"
  export CXXFLAGS="${CFLAGS} -std=gnu++11 -Wno-null-conversion"
  export LIBS="-L${TARGET_PATH}/lib -liconv"
  CONFIGURE="--host=${CROSS_COMPILE} --enable-static --disable-shared --disable-dependency-tracking --with-pic"
  ARCHS=${ARCH}

  if [ ! -d ${TARGET_PATH} ]; then
    #iconv for xerces
    sudo mkdir -p ${TARGET_PATH}/include ${TARGET_PATH}/lib
    sudo cp patches/android-iconv/iconv.h ${TARGET_PATH}/include/
    sudo ${CC} -fPIC -I${TARGET_PATH}/include -std=c99 -o ${TARGET_PATH}/lib/libiconv.o -c patches/android-iconv/iconv.c
    sudo ${AR} rcs ${TARGET_PATH}/lib/libiconv.a ${TARGET_PATH}/lib/libiconv.o
  fi
  ;;
*simulator*)
  echo "Building for iOS Simulator"
  TARGET_PATH=/Library/libdigidocpp.iphonesimulator
  CONFIGURE="--host=arm-apple-darwin --enable-static --disable-shared --disable-dependency-tracking"
  SYSROOT=$(xcrun -sdk iphonesimulator --show-sdk-path)
  : ${ARCHS:="x86_64"}
  : ${IPHONEOS_DEPLOYMENT_TARGET:="12.0"}
  export IPHONEOS_DEPLOYMENT_TARGET
  export CFLAGS="-arch ${ARCHS// / -arch } -isysroot ${SYSROOT}"
  export CXXFLAGS="${CFLAGS} -std=gnu++11 -Wno-null-conversion"
  ;;
*ios*)
  echo "Building for iOS"
  TARGET_PATH=/Library/libdigidocpp.iphoneos
  CONFIGURE="--host=arm-apple-darwin --enable-static --disable-shared --disable-dependency-tracking"
  SYSROOT=$(xcrun -sdk iphoneos --show-sdk-path)
  : ${ARCHS:="arm64"}
  : ${IPHONEOS_DEPLOYMENT_TARGET:="12.0"}
  export IPHONEOS_DEPLOYMENT_TARGET
  export CFLAGS="-arch ${ARCHS// / -arch } -isysroot ${SYSROOT}"
  export CXXFLAGS="${CFLAGS} -std=gnu++11 -Wno-null-conversion"
  ;;
*)
  echo "Building for OSX"
  TARGET_PATH=/Library/libdigidocpp
  CONFIGURE="--disable-static --enable-shared --disable-dependency-tracking"
  SYSROOT=$(xcrun -sdk macosx --show-sdk-path)
  : ${ARCHS:="x86_64 arm64"}
  : ${MACOSX_DEPLOYMENT_TARGET:="10.14"}
  export MACOSX_DEPLOYMENT_TARGET
  export CFLAGS="-arch ${ARCHS// / -arch } "
  export CXXFLAGS="${CFLAGS} -std=gnu++11 -Wno-null-conversion"
  ;;
esac

function xerces {
    echo Building ${XERCES_DIR}
    if [ ! -f ${XERCES_DIR}.tar.xz ]; then
        curl -O -L https://dlcdn.apache.org/xerces/c/3/sources/${XERCES_DIR}.tar.xz
    fi
    rm -rf ${XERCES_DIR}
    tar xf ${XERCES_DIR}.tar.xz
    cd ${XERCES_DIR}
    sed -ie 's!as_fn_error $? "cannot run test program while cross compiling!$as_echo_n "cannot run test program while cross compiling!' configure
    sed -ie 's!SUBDIRS = doc src tests samples!SUBDIRS = src!' Makefile.in 
    case "${ARGS}" in
    *ios*|*simulator*) XERCESCONFIGURE="${CONFIGURE} --enable-transcoder-iconv" ;;
    *) XERCESCONFIGURE=${CONFIGURE} ;;
    esac
    ./configure --prefix=${TARGET_PATH} ${XERCESCONFIGURE}
    make -s
    sudo make install
    cd -
}

function xalan {
    echo Building ${XALAN_DIR}
    if [ ! -f ${XALAN_DIR}.tar.gz ]; then
        curl -O -L https://dlcdn.apache.org/xalan/xalan-c/sources/${XALAN_DIR}.tar.gz
    fi
    rm -rf ${XALAN_DIR}
    tar xf ${XALAN_DIR}.tar.gz
    cd ${XALAN_DIR}
    sed -ie 's!add_subdirectory(samples)!!' CMakeLists.txt
    sed -ie 's!add_subdirectory(Tests)!!' CMakeLists.txt
    sed -ie 's!add_subdirectory(docs/doxygen)!!' CMakeLists.txt
    sed -ie 's!add_subdirectory(src/xalanc/TestXSLT)!!' CMakeLists.txt
    sed -ie 's!add_subdirectory(src/xalanc/TestXPath)!!' CMakeLists.txt
    sed -n '1102,1500!p' src/xalanc/CMakeLists.txt > tmp
    mv tmp src/xalanc/CMakeLists.txt
    case "${ARGS}" in
    *android*)
      cmake \
        -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake \
        -DANDROID_PLATFORM=${ABI} \
        -DANDROID_ABI=${ARCH_ABI} \
        -DCMAKE_INSTALL_PREFIX=${TARGET_PATH} \
        -DCMAKE_FIND_ROOT_PATH=${TARGET_PATH} \
        -DCMAKE_BUILD_TYPE="Release" \
        -DBUILD_SHARED_LIBS=NO \
        .
        make -s MsgCreator || cp ../patches/MsgCreator src/xalanc/Utils/MsgCreator
        make -s && sudo make install
      ;;
    *ios*|*simulator*)
      cmake \
        -DCMAKE_C_COMPILER_WORKS=yes \
        -DCMAKE_CXX_COMPILER_WORKS=yes \
        -DCMAKE_OSX_SYSROOT=${SYSROOT} \
        -DCMAKE_OSX_ARCHITECTURES="${ARCHS// /;}" \
        -DCMAKE_INSTALL_PREFIX=${TARGET_PATH} \
        -DCMAKE_BUILD_TYPE="Release" \
        -DBUILD_SHARED_LIBS=NO \
        . && make -s MsgCreator
        cp ../patches/MsgCreator src/xalanc/Utils/MsgCreator
        make -s && sudo make install
      ;;
    *)
      cmake \
        -DCMAKE_MACOSX_RPATH=NO \
        -DCMAKE_OSX_ARCHITECTURES="${ARCHS// /;}" \
        -DCMAKE_INSTALL_PREFIX=${TARGET_PATH} \
        -DCMAKE_BUILD_TYPE="Release" \
        -DBUILD_SHARED_LIBS=YES \
        . && make -s && sudo make install
      sudo install_name_tool -id ${TARGET_PATH}/lib/libxalanMsg.112.dylib ${TARGET_PATH}/lib/libxalanMsg.*.0.dylib
      sudo install_name_tool -id ${TARGET_PATH}/lib/libxalan-c.112.dylib \
        -change libxalanMsg.112.dylib ${TARGET_PATH}/lib/libxalanMsg.112.dylib ${TARGET_PATH}/lib/libxalan-c.*.0.dylib
      ;;
    esac
    cd -
}

function xml_security {
    echo Building ${XMLSEC_DIR}
    if [ ! -f ${XMLSEC_DIR}.tar.gz ]; then
        curl -O -L https://dlcdn.apache.org/santuario/c-library/${XMLSEC_DIR}.tar.gz
    fi
    rm -rf ${XMLSEC_DIR}
    tar xf ${XMLSEC_DIR}.tar.gz
    cd ${XMLSEC_DIR}
    patch -Np1 -i ../patches/vcpkg-ports/xml-security-c/002_xml-security-c-SHA3.patch
    sed -ie 's!as_fn_error $? "cannot run test program while cross compiling!$as_echo_n "cannot run test program while cross compiling!' configure
    sed -ie 's!#define XSEC_EXPORT!#define XSEC_EXPORT __attribute__ ((visibility("default")))!' xsec/framework/XSECDefs.hpp
    CFLAGS="${CFLAGS} -fvisibility=hidden" \
    CXXFLAGS="${CXXFLAGS} -fvisibility=hidden -fvisibility-inlines-hidden" \
    xerces_CFLAGS="-I${TARGET_PATH}/include" xerces_LIBS="-L${TARGET_PATH}/lib -lxalanMsg -lxalan-c -lxerces-c" \
    openssl_CFLAGS="-I${TARGET_PATH}/include" openssl_LIBS="-L${TARGET_PATH}/lib -lcrypto" \
    ./configure --prefix=${TARGET_PATH} ${CONFIGURE} --with-xalan=${TARGET_PATH}
    sed -ie 's!PROGRAMS = $(bin_PROGRAMS) $(noinst_PROGRAMS)!PROGRAMS = !; s!bin_PROGRAMS = $(am__EXEEXT_2)!bin_PROGRAMS = !' xsec/Makefile
    make -s
    sudo make install
    cd -
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
        curl -O -L http://xmlsoft.org/sources/${LIBXML2_DIR}.tar.gz
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
    cd -
}

function xsd {
    echo Building ${XSD}
    #if [ ! -f ${XSD}.tar.bz2 ]; then
    #    curl -O -L https://www.codesynthesis.com/download/xsd/4.0/macosx/i686/${XSD}.tar.bz2
    #fi
    #rm -rf ${XSD}
    #tar xf ${XSD}.tar.bz2
    #sudo mkdir -p ${TARGET_PATH}/bin ${TARGET_PATH}/include
    #sudo cp ${XSD}/bin/xsd ${TARGET_PATH}/bin/
    #sudo cp -Rf ${XSD}/libxsd/xsd ${TARGET_PATH}/include/
    echo "Install XSD from homebrew, official binaries are 32bit and do not work anymore"
}

function openssl {
    echo Building ${OPENSSL_DIR}
    if [ ! -f ${OPENSSL_DIR}.tar.gz ]; then
        curl -O -L https://www.openssl.org/source/${OPENSSL_DIR}.tar.gz
    fi
    rm -rf ${OPENSSL_DIR}
    tar xf ${OPENSSL_DIR}.tar.gz
    cd ${OPENSSL_DIR}

    sed -ie 's!, "apps"!!' Configure
    sed -ie 's!, "fuzz"!!' Configure
    sed -ie 's!, "test"!!' Configure
    case "${ARGS}" in
    *android*)
        ./Configure android-${ARCH} -D__ANDROID_API__=${ABI} --prefix=${TARGET_PATH} --openssldir=${TARGET_PATH}/ssl no-hw no-engine no-tests no-shared
        make -s
        sudo make install_sw
        ;;
    *)
        for ARCH in ${ARCHS}
        do
            case "${ARCH}" in
            *x86_64*)
                case "${ARGS}" in
                *simulator*) CC="" CFLAGS="" ./Configure iossimulator-xcrun --prefix=${TARGET_PATH} no-shared no-dso no-hw no-asm no-engine ;;
                *) CC="" CFLAGS="" KERNEL_BITS=64 ./config --prefix=${TARGET_PATH} shared no-hw no-engine no-tests enable-ec_nistp_64_gcc_128
                esac
                ;;
            *arm64*)
                case "${ARGS}" in
                *ios*) CC="" CFLAGS="" ./Configure ios64-xcrun --prefix=${TARGET_PATH} no-shared no-dso no-hw no-asm no-engine ;;
                *) CC="" CFLAGS="" MACHINE=arm64 KERNEL_BITS=64 ./config --prefix=${TARGET_PATH} shared no-hw no-engine no-tests enable-ec_nistp_64_gcc_128
                esac
                ;;
            *) CC="" CFLAGS="" ./Configure ios-xcrun --prefix=${TARGET_PATH} no-shared no-dso no-hw no-asm no-engine
            esac
            make -s > /dev/null
            if [[ ${ARCHS} == ${ARCH}* ]]; then
                sudo make install_sw > /dev/null
            else
                make install_sw DESTDIR=${PWD}/${ARCH} > /dev/null
                mkdir -p universal/${TARGET_PATH}/lib
                cd ${ARCH}
                for i in $(find ./${TARGET_PATH}/lib -type f -depth 1); do
                    lipo -create /$i $i -output ../universal/$i
                done
                cd -
                sudo mv universal/${TARGET_PATH}/lib/* ${TARGET_PATH}/lib/
            fi
            make distclean
        done
        ;;
    esac
    cd -
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
        *ios*|*simulator*)
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
*xerces*) xerces ;;
*xalan*) xalan ;;
*xmlsec*) xml_security ;;
*libxml2*) libxml2 ;;
*xsd*) xsd ;;
*openssl*) openssl ;;
*freetype*) freetype ;;
*fontconfig*) fontconfig ;;
*podofo*) podofo ;;
*all*)
    xerces
    openssl
    xalan
    xml_security
    ;;
*)
    echo "Usage:"
    echo "  $0 [target] [task]"
    echo "  target: osx ios iossimulator androidarm androidarm64 androidx86 androidx86_64"
    echo "  tasks: xerces, xalan, openssl, xmlsec, xsd, all, help"
    echo "To control iOS, macOS builds set environment variables:"
    echo " minimum deployment target"
    echo " - MACOSX_DEPLOYMENT_TARGET=10.14"
    echo " - IPHONEOS_DEPLOYMENT_TARGET=12.0"
    echo " archs to build on iOS"
    echo " - ARCHS=\"arm64\" (iOS)"
    echo " - ARCHS=\"x86_64\" (iPhoneSimulator)"
    ;;
esac
