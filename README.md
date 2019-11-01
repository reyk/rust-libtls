# Rust bindings for [LibreSSL]'s [libtls] library.

>
> NOTE: THIS CRATE IS UNDER ACTIVE DEVELOPMENT AND WORK IN PROGRESS.
> !!!DO NOT USE IT YET!!!
>

The [LibreSSL] project provides a free TLS and crypto stack that was forked
from [OpenSSL] in 2014.  The goals are to provide a modernized codebase,
improved security, and to apply best practice development processes.

[LibreSSL] provides C APIs that are compatible to [OpenSSL]'s [libssl] and
[libcrypto] libraries.  It also provides [libtls], a new TLS library that
is designed to make it easier to write foolproof applications.

This crate provides Rust language bindings for [libtls] only, as the other
[LibreSSL] APIs can be used with the existing [rust-openssl] crate.
[LibreSSL] versions 2.7.0 through 3.0.2 (or later) are supported.

## Example

```rust
use libtls::config::{self, TlsConfig};
use libtls::error;

fn tls_server_config() -> error::Result<TlsConfig> {
    let mut tls_config = TlsConfig::new()?;
    tls_config.set_keypair_file("tests/eccert.crt", "tests/eccert.key")?;
    Ok(tls_config)
}

fn main() {
    let tls_config = tls_server_config().unwrap();
}
```

## Copyright and license

Licensed under an OpenBSD-ISC-style license, see [LICENSE] for details.

[LibreSSL]: https://www.libressl.org
[LICENSE]: LICENSE
[OpenSSL]: https://wiki.openssl.org/index.php/Code_Quality
[libcrypto]: https://man.openbsd.org/crypto.3
[libssl]: https://man.openbsd.org/ssl.3
[libtls]: https://man.openbsd.org/tls_init.3
[rust-openssl]: https://docs.rs/openssl/
