#!/bin/bash

case "$@" in
*simulator*)
  echo "Building for iOS Simulator"
  TARGET=iphonesimulator
  : ${ARCHS:="i386 x86_64"}
  ;;
*)
  echo "Building for iOS"
  TARGET=iphoneos
  : ${ARCHS:="armv7 armv7s arm64"}
  ;;
esac

: ${IPHONEOS_DEPLOYMENT_TARGET:="9.0"}
export IPHONEOS_DEPLOYMENT_TARGET
TARGET_PATH=/Library/libdigidocpp.${TARGET}
rm -rf ${TARGET}
mkdir -p ${TARGET}
cd ${TARGET}
cmake \
    -DCMAKE_C_COMPILER_WORKS=yes \
    -DCMAKE_CXX_COMPILER_WORKS=yes \
    -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
    -DCMAKE_OSX_SYSROOT=${TARGET} \
    -DCMAKE_OSX_ARCHITECTURES="${ARCHS// /;}" \
    -DCMAKE_INSTALL_PREFIX=${TARGET_PATH} \
    -DOPENSSL_ROOT_DIR=${TARGET_PATH} \
    -DBoost_INCLUDE_DIR=NOTFOUND \
    -DDOXYGEN_EXECUTABLE=NOTFOUND \
    -DSWIG_EXECUTABLE=NOTFOUND \
    -DIOS=YES \
    -DFRAMEWORK=off \
    -DUSE_KEYCHAIN=off \
    -DBUILD_TOOLS=off \
    -DBUILD_SHARED_LIBS=NO \
    ../../..
make
sudo make install
cd ..
