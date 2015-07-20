#!/bin/bash

echo "Building for android"
TARGET=android
TARGET_PATH=/Library/EstonianIDCard.${TARGET}

rm -rf ${TARGET}
mkdir -p ${TARGET}
cd ${TARGET}
cmake \
    -DCMAKE_TOOLCHAIN_FILE=../android.toolchain.cmake \
    -DANDROID_NATIVE_API_LEVEL=21 \
    -DANDROID_TOOLCHAIN_NAME=arm-linux-androideabi-4.8 \
    -DCMAKE_BUILD_TYPE="RelWithDebInfo" \
    -DCMAKE_INSTALL_PREFIX=${TARGET_PATH} \
    -DCMAKE_C_FLAGS=-DIOAPI_NO_64 \
    -DCMAKE_CXX_FLAGS=-DIOAPI_NO_64 \
    -DOPENSSL_ROOT_DIR=${TARGET_PATH} \
    -DOPENSSL_CRYPTO_LIBRARY=${TARGET_PATH}/lib/libcrypto.a \
    -DOPENSSL_SSL_LIBRARY=${TARGET_PATH}/lib/libssl.a \
    -DXERCESC_INCLUDE_DIR=${TARGET_PATH}/include \
    -DXERCESC_LIBRARY=${TARGET_PATH}/lib/libxerces-c.a \
    -DXMLSECURITYC_INCLUDE_DIR=${TARGET_PATH}/include \
    -DXMLSECURITYC_LIBRARY=${TARGET_PATH}/lib/libxml-security-c.a \
    -DXSD_INCLUDE_DIR=${TARGET_PATH}/include \
    -DXSD_EXECUTABLE=${TARGET_PATH}/bin/xsd \
    -DZLIB_INCLUDE_DIR=${TARGET_PATH}/sysroot/usr/include \
    -DZLIB_LIBRARY=${TARGET_PATH}/sysroot/usr/lib/libz.a \
    -DLIBXML2_INCLUDE_DIR=${TARGET_PATH}/include/libxml2 \
    -DLIBXML2_LIBRARIES=${TARGET_PATH}/lib/libxml2.a \
    -DLIBDIGIDOC_INCLUDE_DIR=${TARGET_PATH}/include \
    -DLIBDIGIDOC_LIBRARY=${TARGET_PATH}/lib/libdigidoc.a \
    -DBUILD_TOOLS=off \
    -DBUILD_TYPE=STATIC \
    ../../..
make
sudo cp src/libdigidoc_java.so ${TARGET_PATH}/lib
cd ..
