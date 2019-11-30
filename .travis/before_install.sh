#!/bin/sh

set -e
set -x

[ -z "${LIBRESSL_DIR}" ] && exit 0

# Install ninja for faster builds
apt-get install apt-get install ninja-build

mkdir -p "${LIBRESSL_DIR}"
cd "${LIBRESSL_DIR}"

curl -sSf -O "https://cdn.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRESSL}.tar.gz"
tar zxf "libressl-${LIBRESSL}.tar.gz"
cd "libressl-${LIBRESSL}"

mkdir build-ninja
cd build-ninja
cmake -G"Ninja" --prefix "${LIBRESSL_DIR}" -D LIBRESSL_ROOT_DIR="${LIBRESSL_DIR}" ..
ninja
ninja test
ninja install

exit 0
