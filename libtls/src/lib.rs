//! Rust language bindings for [LibreSSL]'s [libtls] library.
//!
//! The [LibreSSL] project provides a free TLS and crypto stack that was forked
//! from [OpenSSL] in 2014.  The goals are to provide a modernized codebase,
//! improved security, and to apply best practice development processes.
//!
//! [LibreSSL] provides C APIs that are compatible to [OpenSSL]'s [libssl] and
//! [libcrypto] libraries.  It also provides [libtls], a new TLS library that
//! is designed to make it easier to write foolproof applications.
//!
//! This crate provides Rust language bindings for [libtls] only, as the other
//! [LibreSSL] APIs can be used with the existing [rust-openssl] crate.
//! [LibreSSL] versions 2.7.0 through 3.0.2 (or later) are supported.
//!
//! # Example
//!
//! ```rust
//! use libtls::config::{self, TlsConfig};
//! use libtls::error;
//!
//! fn tls_server_config() -> error::Result<TlsConfig> {
//!     let mut tls_config = TlsConfig::new()?;
//!     tls_config.set_keypair_file("tests/eccert.crt", "tests/eccert.key")?;
//!     Ok(tls_config)
//! }
//!
//! fn main() {
//!     let tls_config = tls_server_config().unwrap();
//! }
//!
//! ```
//!
//! # Copyright and license
//!
//! ```text
//! Copyright (c) 2019 Reyk Floeter <contact@reykfloeter.com>
//! ```
//!
//! The documentation is based on the libtls manpages of the [LibreSSL] project:
//!
//! ```text
//! Copyright (c) 2015, 2016 Bob Beck <beck@openbsd.org>
//! Copyright (c) 2016 Brent Cook <bcook@openbsd.org>
//! Copyright (c) 2017 Claudio Jeker <claudio@openbsd.org>
//! Copyright (c) 2015 Doug Hogan <doug@openbsd.org>
//! Copyright (c) 2017 Ingo Schwarze <schwarze@openbsd.org>
//! Copyright (c) 2014, 2015, 2016, 2017, 2018 Joel Sing <jsing@openbsd.org>
//! Copyright (c) 2015 Reyk Floeter <reyk@openbsd.org>
//! Copyright (c) 2014, 2015 Ted Unangst <tedu@openbsd.org>
//! ```
//!
//! Both are provided under the same [OpenBSD-ISC-style] license:
//!
//! ```text
//! Permission to use, copy, modify, and distribute this software for any
//! purpose with or without fee is hereby granted, provided that the above
//! copyright notice and this permission notice appear in all copies.
//!
//! THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
//! WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
//! MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
//! ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
//! WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
//! ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
//! OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//! ```
//!
//! [LibreSSL]: https://www.libressl.org
//! [OpenBSD-ISC-style]: https://en.wikipedia.org/wiki/ISC_license#OpenBSD_license
//! [OpenSSL]: https://wiki.openssl.org/index.php/Code_Quality
//! [libcrypto]: https://man.openbsd.org/crypto.3
//! [libssl]: https://man.openbsd.org/ssl.3
//! [libtls]: https://man.openbsd.org/tls_init.3
//! [rust-openssl]: https://docs.rs/openssl/

#![doc(
    html_logo_url = "https://www.libressl.org/images/libressl.jpg",
    html_favicon_url = "https://www.libressl.org/favicon.ico"
)]
#![warn(missing_docs)]

extern crate libtls_sys as libtls;

/// TLS configuration for [`Tls`] connections.
///
/// [`Tls`]: ../tls/struct.Tls.html
pub mod config;

/// Error handling.
pub mod error;

/// TLS connections.
pub mod tls;

/// Helper functions.
mod util;

/// TLS API version.
pub use libtls::TLS_API;

use util::*;

/// TLS major/minor protocol version.
#[rustfmt::skip]
pub use libtls::{
    TLS_PROTOCOL_TLSv1_0,
    TLS_PROTOCOL_TLSv1_1,
    TLS_PROTOCOL_TLSv1_2,
    TLS_PROTOCOL_TLSv1,
    TLS_PROTOCOLS_ALL,
    TLS_PROTOCOLS_DEFAULT
};

/// TLS async I/O.
#[rustfmt::skip]
pub use libtls::{
    TLS_WANT_POLLIN,
    TLS_WANT_POLLOUT
};

/// OCSP response (RFC 6960 Section 2.3).
#[rustfmt::skip]
pub use libtls::{
    TLS_OCSP_RESPONSE_SUCCESSFUL,
    TLS_OCSP_RESPONSE_MALFORMED,
    TLS_OCSP_RESPONSE_INTERNALERROR,
    TLS_OCSP_RESPONSE_TRYLATER,
    TLS_OCSP_RESPONSE_SIGREQUIRED,
    TLS_OCSP_RESPONSE_UNAUTHORIZED
};

/// OCSP certificate (RFC 6960 Section 2.2).
#[rustfmt::skip]
pub use libtls::{
    TLS_OCSP_CERT_GOOD,
    TLS_OCSP_CERT_REVOKED,
    TLS_OCSP_CERT_UNKNOWN
};

/// CRL (RFC 5280 Section 5.3.1).
#[rustfmt::skip]
pub use libtls::{
    TLS_CRL_REASON_UNSPECIFIED,
    TLS_CRL_REASON_KEY_COMPROMISE,
    TLS_CRL_REASON_CA_COMPROMISE,
    TLS_CRL_REASON_AFFILIATION_CHANGED,
    TLS_CRL_REASON_SUPERSEDED,
    TLS_CRL_REASON_CESSATION_OF_OPERATION,
    TLS_CRL_REASON_CERTIFICATE_HOLD,
    TLS_CRL_REASON_REMOVE_FROM_CRL,
    TLS_CRL_REASON_PRIVILEGE_WITHDRAWN,
    TLS_CRL_REASON_AA_COMPROMISE
};

/// TLS session.
#[rustfmt::skip]
pub use libtls::{
    TLS_MAX_SESSION_ID_LENGTH,
    TLS_TICKET_KEY_SIZE
};

/// XXX tls_read_cb
pub type TlsReadCb = libtls::tls_read_cb;

/// XXX tls_write_cb
pub type TlsWriteCb = libtls::tls_write_cb;

/// Initialize global data structures.
///
/// The `tls_init` function initializes global data structures.  It is no
/// longer necessary to call this function directly, since it is invoked
/// internally when needed.  It may be called more than once, and may be called
/// concurrently.
///
/// # See also
///
/// [`tls_init(3)`](https://man.openbsd.org/tls_init.3)
#[deprecated(
    since = "LibreSSL 2.7.0",
    note = "It is no longer necessary to call this function."
)]
pub fn tls_init() -> error::Result<()> {
    cvt_io((), unsafe { libtls::tls_init() })
}
