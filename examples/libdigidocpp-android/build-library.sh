#!/bin/bash

case "$@" in
*x86*)
  TARGET_PATH=/Library/EstonianIDCard.androidx86
  ARCH="x86"
  ;;
*arm64*)
  TARGET_PATH=/Library/EstonianIDCard.androidarm64
  ARCH="arm64-v8a"
  ;;
*)
  TARGET_PATH=/Library/EstonianIDCard.androidarm
  ARCH="armeabi"
  ;;
esac

rm -rf build
mkdir -p build
cd build
cmake \
    -DCMAKE_SYSTEM_NAME=Android \
    -DCMAKE_ANDROID_STANDALONE_TOOLCHAIN=${TARGET_PATH} \
    -DCMAKE_ANDROID_ARCH_ABI=${ARCH} \
    -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
    -DCMAKE_INSTALL_PREFIX=${TARGET_PATH} \
    -DCMAKE_C_FLAGS=-DIOAPI_NO_64 \
    -DOPENSSL_ROOT_DIR=${TARGET_PATH} \
    -DBoost_INCLUDE_DIR="" \
    -DBUILD_TOOLS=off \
    -DBUILD_TYPE=STATIC \
    ../../..
make
sudo make install
cd ..
