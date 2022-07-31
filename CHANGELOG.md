# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] - Unreleased
### Added
- Implement `futures::io::AsyncRead` and `futures::io::AsyncWrite` for `libtls::TlsStream` in [tokio-libtls].
### Breaking changes
- Switched tokio version to 0.3.
- Removed `AsyncTlsStream` from [tokio-libtls]. `TlsStream` can now be used in all cases where `AsyncTlsStream` could previously.
- Removed `Error` from [tokio-libtls]. Now just use `libtls::TlsError` instead.

## [1.2.0] - 2020-04-09
### Added
- New with LibreSSL 3.1.0: Support for `TLSv1.3`,
  `Tls::conn_cipher_strength` method.
### Changed
- New upstream release [LibreSSL 3.1.0].

## [1.1.2] - 2019-12-20
### Changed
- Use whitelist for libtls bindings.

## [1.1.1] - 2019-12-20
### Added
- New `accept`, `accept_stream`, `connect`, and `connect_stream`
  functions in [tokio-libtls].
- `examples/` directory.
### Deprecated
- `config::TlsConfig` in favour of `config::Config` in [libtls].
- `config::TlsConfigBuilder` in favour of `config::Builder` in
  [libtls].
- `error::TlsError` in favour of `error::Error` in [libtls].
- `AsyncTls::accept_stream`, `AsyncTls::connect`, and
  `AsyncTls::connect_stream` in [tokio-libtls]; use the new
  module-based functions instead.
- `error::AsyncTlsError` in favour of `error::Error` in
  [tokio-libtls].
- `AsyncTlsOptions` in favour of `Options` in [tokio-libtls].
### Fixed
- Fixed warnings under Rust 1.40.

## [1.1.0] - 2019-12-06
### Added
- Support for [async-await].
- Switched to futures 0.3 and tokio-0.2 for [async-await].
- The [tokio-libtls] crate now requires Rust 1.39 or newer.
### Changed
- Don't export `AsyncRead` and `AsyncWrite` in the prelude.
- Improved `TlsError` error messages to be a bit more verbose.
- Tested several iterations related to `cargo publish` and the `docs.rs` link.
- The [tokio-libtls] `AsyncTls` functions, using `AsyncTlsOptions`.
- Use `tokio::io::{AsyncRead, AsyncWrite}` instead of the `futures` versions.
- `AsyncTlsOptions` to [tokio-libtls].
### Fixed
- Flush is a no-up for the `Tls` object
- Fixed `Tls::accept_*` and `AsyncTls::accept_stream` (server)

## [1.0.0] - 2019-11-11
### Added
- Several changes since the initial import.
- This [CHANGELOG].
- [tokio-libtls] crate to support async I/O with [tokio].
### Changed
- Using upstream release [LibreSSL 3.0.2].
- Split `close()` into `tls_close()` and `close()` as the latter
  returns Rust-style `WouldBlock`.

[LibreSSL 3.1.0]: https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-3.1.0-relnotes.txt
[LibreSSL 3.0.2]: https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-3.0.2-relnotes.txt
[async-await]: https://blog.rust-lang.org/2019/11/07/Async-await-stable.html
[CHANGELOG]: CHANGELOG.md
[tokio]: https://tokio.rs/
[libtls]: https://crates.io/crates/libtls
[tokio-libtls]: https://crates.io/crates/tokio-libtls
[1.2.0]: https://github.com/reyk/rust-libtls/compare/v1.1.2..v1.2.0
[1.1.2]: https://github.com/reyk/rust-libtls/compare/v1.1.1..v1.1.2
[1.1.1]: https://github.com/reyk/rust-libtls/compare/v1.1.0..v1.1.1
[1.1.0]: https://github.com/reyk/rust-libtls/compare/v1.0.0..v1.1.0
[1.0.0]: https://github.com/reyk/rust-libtls/compare/fe1583dbea2c7aa086ed53303030b6f719675f8d...v1.0.0
