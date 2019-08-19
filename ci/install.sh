#!/bin/bash
set -eux

: "${CORES:=2}"
: "${MAKE:=make}"

pushd /
sudo curl -L -o cmake.sh https://github.com/Kitware/CMake/releases/download/v3.14.5/cmake-3.14.5-Linux-x86_64.sh
sudo sh cmake.sh --skip-license
CMAKE=/bin/cmake
popd

# botan
botan_build=${LOCAL_BUILDS}/botan
if [ ! -e "${BOTAN_INSTALL}/lib/libbotan-2.so" ] && \
   [ ! -e "${BOTAN_INSTALL}/lib/libbotan-2.dylib" ]; then

  if [ -d "${botan_build}" ]; then
    rm -rf "${botan_build}"
  fi

  git clone --depth 1 https://github.com/randombit/botan "${botan_build}"
  pushd "${botan_build}"
  ./configure.py --prefix="${BOTAN_INSTALL}" --with-debug-info --cxxflags="-fno-omit-frame-pointer"
  ${MAKE} -j${CORES} install
  popd
fi

# json-c
jsonc_build=${LOCAL_BUILDS}/json-c
if [ ! -e "${JSONC_INSTALL}/lib/libjson-c.so" ] && \
   [ ! -e "${JSONC_INSTALL}/lib/libjson-c.dylib" ]; then

   if [ -d "${jsonc_build}" ]; then
     rm -rf "${jsonc_build}"
   fi

  mkdir -p "${jsonc_build}"
  pushd ${jsonc_build}
  wget https://s3.amazonaws.com/json-c_releases/releases/json-c-0.12.1.tar.gz -O json-c.tar.gz
  tar xzf json-c.tar.gz --strip 1

  autoreconf -ivf
  env CFLAGS="-fno-omit-frame-pointer -g" ./configure --prefix="${JSONC_INSTALL}"
  ${MAKE} -j${CORES} install
  popd
fi

# rnp
rnp_build=${LOCAL_BUILDS}/rnp
if [ ! -e "${RNP_INSTALL}/lib/librnp.so" ] && \
   [ ! -e "${RNP_INSTALL}/lib/librnp.dylib" ]; then

  git clone https://github.com/rnpgp/rnp ${rnp_build}
  pushd "${rnp_build}"
  git checkout "$RNP_VERSION"
  ${CMAKE} \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DBUILD_SHARED_LIBS=yes \
    -DBUILD_TESTING=no \
    -DCMAKE_PREFIX_PATH="${BOTAN_INSTALL};${JSONC_INSTALL}" \
    -DCMAKE_INSTALL_PREFIX="${RNP_INSTALL}" \
    .
  ${MAKE} -j${CORES} install
  popd
fi

