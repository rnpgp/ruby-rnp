#!/bin/bash
set -eux

: "${CORES:=2}"

: "${MAKE:=make}"

# botan
botan_build=${LOCAL_BUILDS}/botan
if [ ! -e "${BOTAN_INSTALL}/lib/libbotan-2.so" ] && \
   [ ! -e "${BOTAN_INSTALL}/lib/libbotan-2.dylib" ]; then

  if [ -d "${botan_build}" ]; then
    rm -rf "${botan_build}"
  fi

  git clone https://github.com/randombit/botan "${botan_build}"
  pushd "${botan_build}"
  ./configure.py --prefix="${BOTAN_INSTALL}" --with-debug-info --cxxflags="-fno-omit-frame-pointer"
  ${MAKE} -j${CORES} install
  popd
fi

# cmocka
cmocka_build=${LOCAL_BUILDS}/cmocka
if [ ! -e "${CMOCKA_INSTALL}/lib/libcmocka.so" ] && \
   [ ! -e "${CMOCKA_INSTALL}/lib/libcmocka.dylib" ]; then

  if [ -d "${cmocka_build}" ]; then
    rm -rf "${cmocka_build}"
  fi

  git clone git://git.cryptomilk.org/projects/cmocka.git ${cmocka_build}
  cd ${cmocka_build}
  git checkout tags/cmocka-1.1.1

  cd "${LOCAL_BUILDS}"
  mkdir -p cmocka-build
  pushd cmocka-build
  cmake \
    -DCMAKE_INSTALL_DIR="${CMOCKA_INSTALL}" \
    -DLIB_INSTALL_DIR="${CMOCKA_INSTALL}/lib" \
    -DINCLUDE_INSTALL_DIR="${CMOCKA_INSTALL}/include" \
    "${LOCAL_BUILDS}/cmocka"
  ${MAKE} -j${CORES} all install
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

  git clone https://github.com/riboseinc/rnp ${rnp_build}
  pushd "${rnp_build}"
  git checkout "$RNP_VERSION"
  autoreconf -vfi
  ./configure \
    --with-botan="${BOTAN_INSTALL}" \
    --with-jsonc="${JSONC_INSTALL}" \
    --with-cmocka="${CMOCKA_INSTALL}" \
    --prefix="${RNP_INSTALL}"
  ${MAKE} -j${CORES} install
  popd
fi

