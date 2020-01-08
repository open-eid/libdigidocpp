#!/bin/bash

if [ "$#" -eq 0 ]; then
  echo "Usage:"
  echo "  $0 target [maketask]"
  echo "  target: osx ios iossimulator androidarm androidarm64 androidx86 androidx86_64"
  echo "To control iOS, macOS builds set environment variables:"
  echo " minimum deployment target"
  echo " - MACOSX_DEPLOYMENT_TARGET=10.11"
  echo " - IPHONEOS_DEPLOYMENT_TARGET=9.0"
  echo " archs to build on iOS"
  echo " - ARCHS=\"armv7 arm64\" (iOS)"
  echo " - ARCHS=\"x86_64\" (iPhoneSimulator)"
  exit
fi

case "$@" in
*android*)
  case "$@" in
  *x86_64*)
    TARGET=androidx86_64
    ARCH="x86_64"
    ;;
  *x86*)
    TARGET=androidx86
    ARCH="x86"
    ;;
  *arm64*)
    TARGET=androidarm64
    ARCH="arm64-v8a"
    ;;
  *)
    TARGET=androidarm
    ARCH="armeabi-v7a"
    ;;
  esac
  TARGET_PATH=/Library/libdigidocpp.${TARGET}
  CMAKEARGS="
    -DCMAKE_SYSTEM_NAME=Android \
    -DCMAKE_SYSTEM_VERSION=21 \
    -DCMAKE_ANDROID_STANDALONE_TOOLCHAIN=${TARGET_PATH} \
    -DCMAKE_ANDROID_ARCH_ABI=${ARCH} \
    -DCMAKE_C_FLAGS='-DIOAPI_NO_64' \
    -DCMAKE_CXX_FLAGS='-Oz' \
    -DBoost_INCLUDE_DIR=NOTFOUND \
    -DDOXYGEN_EXECUTABLE=NOTFOUND \
    -DBUILD_TOOLS=NO \
    -DBUILD_SHARED_LIBS=NO"
  ;;
*ios*)
  case "$@" in
  *simulator*)
    echo "Building for iOS Simulator"
    TARGET=iphonesimulator
    : ${ARCHS:="x86_64"}
    ;;
  *)
    echo "Building for iOS"
    TARGET=iphoneos
    : ${ARCHS:="armv7 arm64"}
    ;;
  esac
  TARGET_PATH=/Library/libdigidocpp.${TARGET}
  : ${IPHONEOS_DEPLOYMENT_TARGET:="9.0"}
  export IPHONEOS_DEPLOYMENT_TARGET
  CMAKEARGS="
    -DCMAKE_C_COMPILER_WORKS=yes \
    -DCMAKE_CXX_COMPILER_WORKS=yes \
    -DCMAKE_OSX_SYSROOT=${TARGET} \
    -DCMAKE_OSX_ARCHITECTURES='${ARCHS// /;}' \
    -DIOS=YES \
    -DFRAMEWORK=off \
    -DUSE_KEYCHAIN=off \
    -DSWIG_EXECUTABLE=NOTFOUND \
    -DBoost_INCLUDE_DIR=NOTFOUND \
    -DDOXYGEN_EXECUTABLE=NOTFOUND \
    -DBUILD_TOOLS=NO \
    -DBUILD_SHARED_LIBS=NO"
  ;;
*)
  echo "Building for macOS"
  TARGET=macOS
  TARGET_PATH=/Library/libdigidocpp
  : ${ARCHS:="x86_64"}
  : ${MACOSX_DEPLOYMENT_TARGET:="10.11"}
  export MACOSX_DEPLOYMENT_TARGET
esac

rm -rf ${TARGET}
mkdir -p ${TARGET}
cd ${TARGET}
cmake \
    -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
    -DCMAKE_INSTALL_PREFIX=${TARGET_PATH} \
    -DOPENSSL_ROOT_DIR=${TARGET_PATH} \
    -DXercesC_ROOT=${TARGET_PATH} \
    ${CMAKEARGS} \
    ..
make
sudo make ${@:2}
cd ..
