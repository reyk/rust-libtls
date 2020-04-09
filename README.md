# Rust bindings for [LibreSSL]'s [libtls].

[![Crates.IO](https://img.shields.io/crates/v/libtls.svg)](https://crates.io/crates/libtls)
[![docs.rs](https://docs.rs/libtls/badge.svg)](https://docs.rs/libtls)
[![Build Status](https://travis-ci.org/reyk/rust-libtls.svg?branch=master)](https://travis-ci.org/reyk/rust-libtls)
[![License](https://img.shields.io/badge/license-ISC-blue.svg)](https://raw.githubusercontent.com/reyk/rust-libtls/master/LICENSE)

[Documentation], [Changelog]

The [LibreSSL] project provides a free TLS and crypto stack that was
forked from [OpenSSL] in 2014.  The goals are to provide a modernized
codebase, improved security, and to apply best practice development
processes.

[LibreSSL] provides C APIs that are compatible to [OpenSSL]'s [libssl]
and [libcrypto] libraries.  It also provides [libtls], a new TLS
library that is designed to make it easier to write foolproof
applications.

This workspace of Rust crates provides language bindings for [libtls]
only, as the other [LibreSSL] APIs can be used with the existing
[rust-openssl] crate.  [LibreSSL] versions 2.9.0 through 3.1.0 (or
later) are supported.

The following crates are included:
- [libtls-sys]: FFI bindings.
- [libtls]: Rust bindings.
- [tokio-libtls]: [Tokio] bindings.

## Minimum Rust version

Async I/O with [tokio-libtls] requires Rust 1.39 or later for
[async-await].  This crate does not provide any backwards
compatibility but you can use version `1.0.0` on older Rust versions.

## Examples

See the [examples] directory for various examples to configure,
establish, and connect synchronous and asynchronous TLS connections.
The following selected example creates a non-blocking and asynchronous
TLS connection using [Tokio] and the [tokio-libtls] crate:

```rust
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_libtls::prelude::*;

async fn async_https_connect(servername: &str) -> io::Result<()> {
    let addr = &(servername.to_owned() + ":443");

    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: {}\r\n\
         Connection: close\r\n\r\n",
        servername
    );

    let config = Builder::new().build()?;
    let mut tls = connect(addr, &config, None).await?;
    tls.write_all(request.as_bytes()).await?;

    let mut buf = vec![0u8; 1024];
    tls.read_exact(&mut buf).await?;

    let ok = b"HTTP/1.1 200 OK\r\n";
    assert_eq!(&buf[..ok.len()], ok);

    Ok(())
}

#[tokio::main]
async fn main() {
    async_https_connect("www.example.com").await.unwrap();
}
```


## Copyright and license

Licensed under an OpenBSD-ISC-style license, see [LICENSE] for details.

[Changelog]: CHANGELOG.md
[Documentation]: https://docs.rs/libtls
[LICENSE]: LICENSE
[LibreSSL]: https://www.libressl.org
[OpenSSL]: https://wiki.openssl.org/index.php/Code_Quality
[Tokio]: https://tokio.rs/
[async-await]: https://blog.rust-lang.org/2019/11/07/Async-await-stable.html
[examples]: https://github.com/reyk/rust-libtls/tree/master/examples
[libcrypto]: https://man.openbsd.org/crypto.3
[libssl]: https://man.openbsd.org/ssl.3
[libtls-sys]: https://crates.io/crates/libtls
[libtls]: https://crates.io/crates/libtls
[libtls]: https://man.openbsd.org/tls_init.3
[rust-openssl]: https://docs.rs/openssl/
[tokio-libtls]: https://crates.io/crates/tokio-libtls
