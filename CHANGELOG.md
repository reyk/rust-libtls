# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2019-11-11
# Added
- This [CHANGELOG].
# Changed
- Split `close()` into `tls_close()` and `close()` as the latter
  returns Rust-style `WouldBlock`.

## [1.0.0-alpha8] - 2019-11-04

## [1.0.0-alpha7] - 2019-11-04
# Added
- [tokio-libtls] crate to support async I/O with [tokio].

## [1.0.0-alpha6] - 2019-11-02
# Added
- Several changes since the initial import.

[CHANGELOG]: CHANGELOG.md
[tokio]: https://tokio.rs/
[tokio-libtls]: https://crates.io/crates/tokio-libtls
[1.0.0-alpha7]: https://github.com/reyk/rust-libtls/compare/v1.0.0-alpha6...v1.0.0-alpha7
[1.0.0-alpha6]: https://github.com/reyk/rust-libtls/compare/fe1583dbea2c7aa086ed53303030b6f719675f8d...v1.0.0-alpha6
