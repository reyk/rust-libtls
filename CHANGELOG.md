# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0-alpha.2] - 2019-11-26
### Added
- `AsyncTlsOptions` to [tokio-libtls].
### Changed
- Updated [tokio-libtls] to use [tokio] version `0.2.0`.
- The [tokio-libtls] `AsyncTls` functions, using `AsyncTlsOptions`.
- Version numbering to use the `x.x.x-alpha.x` syntax.
### Removed
- The `extern crate` definitions.

## [1.1.0-alpha1] - 2019-11-11
### Added
- Support for [async-await].
### Changed
- Switched to futures 0.3 and tokio-0.2 for [async-await].
- The [tokio-libtls] crate now requires Rust 1.39 or newer.

## [1.0.0] - 2019-11-11
### Added
- This [CHANGELOG].
### Changed
- Split `close()` into `tls_close()` and `close()` as the latter
  returns Rust-style `WouldBlock`.

## [1.0.0-alpha8] - 2019-11-04

## [1.0.0-alpha7] - 2019-11-04
### Added
- [tokio-libtls] crate to support async I/O with [tokio].

## [1.0.0-alpha6] - 2019-11-02
### Added
- Several changes since the initial import.

[async-await]: https://blog.rust-lang.org/2019/11/07/Async-await-stable.html
[CHANGELOG]: CHANGELOG.md
[tokio]: https://tokio.rs/
[tokio-libtls]: https://crates.io/crates/tokio-libtls
[1.1.0-alpha.2]: https://github.com/reyk/rust-libtls/compare/v1.1.0-alpha1..v1.1.0-alpha.2
[1.1.0-alpha1]: https://github.com/reyk/rust-libtls/compare/v1.0.0...v1.1.0-alpha1
[1.0.0]: https://github.com/reyk/rust-libtls/compare/v1.0.0-alpha8...v1.0.0
[1.0.0-alpha8]: https://github.com/reyk/rust-libtls/compare/v1.0.0-alpha7...v1.0.0-alpha8
[1.0.0-alpha7]: https://github.com/reyk/rust-libtls/compare/v1.0.0-alpha6...v1.0.0-alpha7
[1.0.0-alpha6]: https://github.com/reyk/rust-libtls/compare/fe1583dbea2c7aa086ed53303030b6f719675f8d...v1.0.0-alpha6

