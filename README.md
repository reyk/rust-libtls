# Rust bindings for [LibreSSL]'s [libtls].

[![Crates.IO](https://img.shields.io/crates/v/libtls.svg)](https://crates.io/crates/libtls)
[![Build Status](https://travis-ci.org/reyk/rust-libtls.svg?branch=master)](https://travis-ci.org/reyk/rust-libtls)
[![License](https://img.shields.io/badge/license-ISC-blue.svg)](https://raw.githubusercontent.com/reyk/rust-libtls/master/LICENSE)

[Documentation](https://reyk.github.io/rust-libtls/libtls/).

The [LibreSSL] project provides a free TLS and crypto stack that was forked
from [OpenSSL] in 2014.  The goals are to provide a modernized codebase,
improved security, and to apply best practice development processes.

[LibreSSL] provides C APIs that are compatible to [OpenSSL]'s [libssl] and
[libcrypto] libraries.  It also provides [libtls], a new TLS library that
is designed to make it easier to write foolproof applications.

This workspace of Rust crates provides language bindings for [libtls]
only, as the other [LibreSSL] APIs can be used with the existing
[rust-openssl] crate.  [LibreSSL] versions 2.9.0 through 3.0.2 (or
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

```rust
use libtls::config::{self, TlsConfig};
use libtls::error;

fn tls_server_config() -> error::Result<TlsConfig> {
    let mut tls_config = TlsConfig::new()?;
    tls_config.set_keypair_file("tests/eccert.crt", "tests/eccert.key")?;
    tls_config.set_protocols(libtls_sys::TLS_PROTOCOL_TLSv1_2);
    Ok(tls_config)
}

fn main() {
    let tls_config = tls_server_config().unwrap();
}
```

The same configuration can be created using the `TlsConfigBuilder`
builder pattern:

```rust
fn tls_server_config() -> error::Result<TlsConfig> {
    let tls_config = TlsConfigBuilder::new()
        .keypair_file("tests/eccert.crt", "tests/eccert.key", None)
        .protocols(libtls_sys::TLS_PROTOCOL_TLSv1_2)
        .build()?;
    Ok(tls_config)
}
```

A TLS connection:

```rust
use libtls::config::TlsConfigBuilder;
use libtls::error;
use std::io::{Read, Write};

fn sync_https_connect(servername: &str) -> error::Result<()> {
    let addr = &(servername.to_owned() + ":443");

    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: {}\r\n\
         Connection: close\r\n\r\n",
        servername
    );

    let mut tls = TlsConfigBuilder::new().client()?;

    tls.connect(addr, None)?;
    tls.write(request.as_bytes())?;

    let mut buf = vec![0u8; 1024];
    tls.read(&mut buf)?;

    let ok = b"HTTP/1.1 200 OK\r\n";
    assert_eq!(&buf[..ok.len()], ok);

    Ok(())
}

fn main() {
    sync_https_connect("www.example.com").unwrap();
}
```

A non-blocking and asynchronous TLS connection using [Tokio] and the
[tokio-libtls] crate:

```rust
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_libtls::prelude::*;

async fn async_https_connect(servername: String) -> io::Result<()> {
    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: {}\r\n\
         Connection: close\r\n\r\n",
        servername
    );

    let config = TlsConfigBuilder::new().build()?;
    let mut tls = AsyncTls::connect(&(servername + ":443"), &config).await?;
    tls.write_all(request.as_bytes()).await?;

    let mut buf = vec![0u8; 1024];
    tls.read_exact(&mut buf).await?;

    let ok = b"HTTP/1.1 200 OK\r\n";
    assert_eq!(&buf[..ok.len()], ok);

    Ok(())
}

#[tokio::main]
async fn main() {
   async_https_connect("www.example.com".to_owned()).await.unwrap();
}
```

## Copyright and license

Licensed under an OpenBSD-ISC-style license, see [LICENSE] for details.

[async-await]: https://blog.rust-lang.org/2019/11/07/Async-await-stable.html
[LICENSE]: LICENSE
[LibreSSL]: https://www.libressl.org
[OpenSSL]: https://wiki.openssl.org/index.php/Code_Quality
[Tokio]: https://tokio.rs/
[libcrypto]: https://man.openbsd.org/crypto.3
[libssl]: https://man.openbsd.org/ssl.3
[libtls-sys]: https://crates.io/crates/libtls
[libtls]: https://crates.io/crates/libtls
[libtls]: https://man.openbsd.org/tls_init.3
[rust-openssl]: https://docs.rs/openssl/
[tokio-libtls]: https://crates.io/crates/tokio-libtls
