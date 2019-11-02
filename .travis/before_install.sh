#!/bin/sh

set -e
set -x

[ -z "${LIBRESSL_DIR}" ] && exit 0

mkdir -p "${LIBRESSL_DIR}"
cd "${LIBRESSL_DIR}"

curl -sSf -O "https://cdn.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRESSL}.tar.gz"
tar zxf "libressl-${LIBRESSL}.tar.gz"
cd "libressl-${LIBRESSL}"
./configure --prefix="${LIBRESSL_DIR}" --with-openssldir="${LIBRESSL_DIR}"
make -j"$(nproc)"
make install

exit 0
