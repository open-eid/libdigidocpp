#!/bin/bash

case "$@" in
*x86*)
  TARGET_PATH=/Library/libdigidocpp.androidx86
  ARCH="x86"
  ;;
*arm64*)
  TARGET_PATH=/Library/libdigidocpp.androidarm64
  ARCH="arm64-v8a"
  ;;
*)
  TARGET_PATH=/Library/libdigidocpp.androidarm
  ARCH="armeabi-v7a"
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
    -DCMAKE_C_FLAGS="-DIOAPI_NO_64 -Oz" \
    -DCMAKE_CXX_FLAGS="-Oz" \
    -DOPENSSL_ROOT_DIR=${TARGET_PATH} \
    -DBoost_INCLUDE_DIR="" \
    -DBUILD_TOOLS=off \
    -DBUILD_SHARED_LIBS=NO \
    -DDOXYGEN_EXECUTABLE=NOTFOUND \
    ../../..
make
sudo make install
cd ..
