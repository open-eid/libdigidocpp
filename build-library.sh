#!/bin/bash

set -e

if [ "$#" -eq 0 ]; then
  echo "Usage:"
  echo "  $0 target [maketask]"
  echo "  target: osx ios iossimulator ioscatalyst androidarm androidarm64 androidx86 androidx86_64"
  echo "To control iOS, macOS builds set environment variables:"
  echo " minimum deployment target"
  echo " - MACOSX_DEPLOYMENT_TARGET=10.15"
  echo " - IPHONEOS_DEPLOYMENT_TARGET=12.0"
  echo " archs to build on macOS/iOS"
  echo " - ARCHS=\"arm64 x86_64\" (macOS)"
  echo " - ARCHS=\"arm64\" (iOS)"
  echo " - ARCHS=\"arm64 x86_64\" (iPhoneSimulator)"
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
  : ${ANDROID_NDK_HOME:=$(ls -d /Volumes/android-ndk-r*/AndroidNDK*.app/Contents/NDK)}
  TARGET_PATH=/Library/libdigidocpp.${TARGET}
  CMAKEARGS="
    -DCMAKE_FIND_ROOT_PATH=${TARGET_PATH};/usr/local;/opt/homebrew \
    -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake \
    -DANDROID_PLATFORM=28 \
    -DANDROID_ABI=${ARCH} \
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
    SYSROOT=iphonesimulator
    : ${ARCHS:="arm64 x86_64"}
    ;;
  *catalyst*)
    echo "Building for iOS macOS Catalyst"
    TARGET=iphonecatalyst
    SYSROOT=macosx
    export CFLAGS="-target x86_64-apple-ios-macabi"
    export CXXFLAGS="-target x86_64-apple-ios-macabi"
    : ${ARCHS:="arm64 x86_64"}
    ;;
  *)
    echo "Building for iOS"
    TARGET=iphoneos
    SYSROOT=iphoneos
    : ${ARCHS:="arm64"}
    ;;
  esac
  TARGET_PATH=/Library/libdigidocpp.${TARGET}
  : ${IPHONEOS_DEPLOYMENT_TARGET:="12.0"}
  export IPHONEOS_DEPLOYMENT_TARGET
  CMAKEARGS="
    -DCMAKE_OSX_SYSROOT=${SYSROOT} \
    -DFRAMEWORK=off \
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
  : ${ARCHS:="arm64 x86_64"}
  : ${MACOSX_DEPLOYMENT_TARGET:="10.15"}
  export MACOSX_DEPLOYMENT_TARGET
esac

cmake --fresh -B ${TARGET} -S . \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=${TARGET_PATH} \
    -DCMAKE_OSX_ARCHITECTURES="${ARCHS// /;}" \
    -DOPENSSL_ROOT_DIR=${TARGET_PATH} \
    -DXercesC_ROOT=${TARGET_PATH} \
    ${CMAKEARGS}
cmake --build ${TARGET}

while test $# -gt 0; do
    case "$1" in
        android*|*ios*|*mac*|*osx*) ;;
        install*) sudo cmake --build ${TARGET} --target $1 ;;
        *) cmake --build ${TARGET} --target $1 ;;
    esac
    shift
done
