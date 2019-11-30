#!/bin/sh

set -e
set -x

[ -z "${LIBRESSL_DIR}" ] && exit 0

mkdir -p "${LIBRESSL_DIR}"
cd "${LIBRESSL_DIR}"

curl -sSf -O "https://cdn.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRESSL}.tar.gz"
tar zxf "libressl-${LIBRESSL}.tar.gz"
cd "libressl-${LIBRESSL}"

export LIBRESSL_ROOT_DIR=${LIBRESSL_DIR}

mkdir build-ninja
cd build-ninja
cmake -G"Ninja" --prefix "${LIBRESSL_DIR}" ..
ninja
ninja install

exit 0
