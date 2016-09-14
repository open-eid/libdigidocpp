#!/bin/bash

case "$@" in
*x86*)
  echo "Building for android X86"
  TARGET_PATH=/Library/EstonianIDCard.androidx86
  CROSS_COMPILE=i686-linux-android
  ;;
*arm64*)
  echo "Building for android ARM64"
  TARGET_PATH=/Library/EstonianIDCard.androidarm64
  CROSS_COMPILE=aarch64-linux-android
  ;;
*)
  echo "Building for android ARM"
  TARGET_PATH=/Library/EstonianIDCard.androidarm
  CROSS_COMPILE=arm-linux-androideabi
  ;;
esac

rm -rf build
mkdir -p build
cd build
cmake \
    -DCMAKE_SYSTEM_NAME=Android \
    -DCMAKE_C_COMPILER=${TARGET_PATH}/bin/${CROSS_COMPILE}-clang \
    -DCMAKE_CXX_COMPILER=${TARGET_PATH}/bin/${CROSS_COMPILE}-clang++ \
    -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
    -DCMAKE_INSTALL_PREFIX=${TARGET_PATH} \
    -DCMAKE_C_FLAGS=-DIOAPI_NO_64 \
    -DCMAKE_CXX_FLAGS=-DIOAPI_NO_64 \
    -DOPENSSL_ROOT_DIR=${TARGET_PATH} \
    -DZLIB_INCLUDE_DIR=${TARGET_PATH}/sysroot/usr/include \
    -DZLIB_LIBRARY=${TARGET_PATH}/sysroot/usr/lib/libz.so \
    -DICONV_LIBRARIES=${TARGET_PATH}/sysroot/usr/lib/libiconv.a \
    -DANDROID=YES \
    -DBUILD_TOOLS=off \
    -DBUILD_TYPE=STATIC \
    ../../..
make
sudo make install
cd ..
