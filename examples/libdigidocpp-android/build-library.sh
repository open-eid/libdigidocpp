#!/bin/bash

echo "Building for android"
case "$@" in
*x86*)
  TOOLCHAIN=x86-4.9
  ANDROID_ABI=x86
  TARGET_PATH=/Library/EstonianIDCard.androidx86
  ;;
*)
  TOOLCHAIN=arm-linux-androideabi-4.9
  ANDROID_ABI=armeabi-v7a
  TARGET_PATH=/Library/EstonianIDCard.androidarm
  ;;
esac

rm -rf build
mkdir -p build
cd build
cmake \
    -DCMAKE_TOOLCHAIN_FILE=../android.toolchain.cmake \
    -DANDROID_NATIVE_API_LEVEL=19 \
    -DANDROID_TOOLCHAIN_NAME=${TOOLCHAIN} \
    -DANDROID_ABI=${ANDROID_ABI} \
    -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
    -DCMAKE_INSTALL_PREFIX=${TARGET_PATH} \
    -DCMAKE_C_FLAGS=-DIOAPI_NO_64 \
    -DCMAKE_CXX_FLAGS=-DIOAPI_NO_64 \
    -DOPENSSL_ROOT_DIR=${TARGET_PATH} \
    -DZLIB_INCLUDE_DIR=${TARGET_PATH}/sysroot/usr/include \
    -DZLIB_LIBRARY=${TARGET_PATH}/sysroot/usr/lib/libz.so \
    -DLIBXML2_INCLUDE_DIR=${TARGET_PATH}/include/libxml2 \
    -DLIBXML2_LIBRARIES=${TARGET_PATH}/lib/libxml2.a \
    -DBUILD_TOOLS=off \
    -DBUILD_TYPE=STATIC \
    ../../..
make
sudo make install
cd ..
