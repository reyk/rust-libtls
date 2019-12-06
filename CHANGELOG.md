# Changelog

All notable changes to this project will be documented in this file.

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
- Split `close()` into `tls_close()` and `close()` as the latter
  returns Rust-style `WouldBlock`.

[async-await]: https://blog.rust-lang.org/2019/11/07/Async-await-stable.html
[CHANGELOG]: CHANGELOG.md
[tokio]: https://tokio.rs/
[tokio-libtls]: https://crates.io/crates/tokio-libtls
[1.1.0]: https://github.com/reyk/rust-libtls/compare/v1.0.0..v1.1.0
[1.0.0]: https://github.com/reyk/rust-libtls/compare/fe1583dbea2c7aa086ed53303030b6f719675f8d...v1.0.0
