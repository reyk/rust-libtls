// Copyright (c) 2019 Reyk Floeter <contact@reykfloeter.com>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//
// The documentation is based on libtls man pages of the LibreSSL project,
// provided under the same ISC-style license (see https://www.libressl.org/):
//
// Copyright (c) 2015, 2016 Bob Beck <beck@openbsd.org>
// Copyright (c) 2016 Brent Cook <bcook@openbsd.org>
// Copyright (c) 2017 Claudio Jeker <claudio@openbsd.org>
// Copyright (c) 2015 Doug Hogan <doug@openbsd.org>
// Copyright (c) 2017 Ingo Schwarze <schwarze@openbsd.org>
// Copyright (c) 2014, 2015, 2016, 2017, 2018 Joel Sing <jsing@openbsd.org>
// Copyright (c) 2015 Reyk Floeter <reyk@openbsd.org>
// Copyright (c) 2014, 2015 Ted Unangst <tedu@openbsd.org>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! TLS clients or servers are created with with the [`Tls`] struct
//! and configured with the [`TlsConfig`] configuration context.
//!
//! [`Tls`]: struct.Tls.html
//! [`TlsConfig`]: ../config/struct.TlsConfig.html

use std::io;

use super::config::TlsConfig;
use super::error::Result;
use super::*;

/// TLS connection clients and servers.
///
/// A TLS connection is represented as a [`Tls`] object called a
/// "context".  A new context is created by either the [`Tls::client`]
/// or [`Tls::server`] functions.  [`Tls::client`] is used in TLS client
/// programs, [`Tls::server`] in TLS server programs.
///
/// The context can then be configured with the [`configure`] method.
/// The same [`TlsConfig`] object can be used to configure multiple contexts.
///
/// After configuration, [`connect`] can be called on objects created with
/// [`Tls::client`], and [`accept_socket`] on objects created with
/// [`Tls::server`].
///
/// After use, a TLS context should be closed with [`close`], which
/// is also called when the object is [dropped]. A TLS context can be
/// reset by calling [`reset`], allowing for it to be reused.
///
/// [`Tls`]: struct.Tls.html
/// [`Tls::client`]: struct.Tls.html#method.client
/// [`Tls::server`]: struct.Tls.html#method.server
/// [`configure`]: struct.Tls.html#method.configure
/// [`TlsConfig`]: ../config/struct.TlsConfig.html
/// [`connect`]: struct.Tls.html#method.connect
/// [`accept_socket`]: struct.Tls.html#method.accept_socket
/// [`close`]: struct.Tls.html#method.close
/// [`reset`]: struct.Tls.html#method.reset
/// [dropped]: struct.Tls.html#impl-Drop
pub struct Tls(*mut libtls::tls);

impl Tls {
    fn new(f: unsafe extern "C" fn() -> *mut libtls::tls) -> io::Result<Self> {
        let tls = unsafe { f() };
        if tls.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Tls(tls))
        }
    }

    /// Create a new TLS client.
    ///
    /// The `client` is used to create connections in TLS client programs.
    ///
    /// # See also
    ///
    /// [`tls_client(3)`](https://man.openbsd.org/tls_client.3)
    pub fn client() -> io::Result<Self> {
        Self::new(libtls::tls_client)
    }

    /// Create a new TLS server.
    ///
    /// The `server` is used to accept connections in TLS server programs.
    ///
    /// # See also
    ///
    /// [`tls_server(3)`](https://man.openbsd.org/tls_server.3)
    pub fn server() -> io::Result<Self> {
        Self::new(libtls::tls_server)
    }

    ///
    ///
    /// The `configure` method
    ///
    /// # See also
    ///
    /// [`tls_configure(3)`](https://man.openbsd.org/tls_configure.3)
    pub fn configure(&mut self, config: &mut TlsConfig) -> Result<()> {
        cvt(self, unsafe { libtls::tls_configure(self.0, config.0) })
    }

    /// Reset the TLS connection.
    ///
    /// A TLS context can be `reset`, allowing for it to be reused.
    ///
    /// # See also
    ///
    /// [`tls_reset(3)`](https://man.openbsd.org/tls_reset.3)
    pub fn reset(&mut self) {
        unsafe { libtls::tls_reset(self.0) };
    }

    //
    //
    // The `accept_fds` method
    //
    // # See also
    //
    // [`tls_accept_fds(3)`](https://man.openbsd.org/tls_accept_fds.3)

    //
    //
    // The `accept_socket` method
    //
    // # See also
    //
    // [`tls_accept_socket(3)`](https://man.openbsd.org/tls_accept_socket.3)

    //
    //
    // The `accept_cbs` method
    //
    // # See also
    //
    // [`tls_accept_cbs(3)`](https://man.openbsd.org/tls_accept_cbs.3)

    //
    //
    // The `connect` method
    //
    // # See also
    //
    // [`tls_connect(3)`](https://man.openbsd.org/tls_connect.3)

    //
    //
    // The `connect_fds` method
    //
    // # See also
    //
    // [`tls_connect_fds(3)`](https://man.openbsd.org/tls_connect_fds.3)

    //
    //
    // The `connect_servername` method
    //
    // # See also
    //
    // [`tls_connect_servername(3)`](https://man.openbsd.org/tls_connect_servername.3)

    //
    //
    // The `connect_socket` method
    //
    // # See also
    //
    // [`tls_connect_socket(3)`](https://man.openbsd.org/tls_connect_socket.3)

    //
    //
    // The `connect_cbs` method
    //
    // # See also
    //
    // [`tls_connect_cbs(3)`](https://man.openbsd.org/tls_connect_cbs.3)

    //
    //
    // The `handshake` method
    //
    // # See also
    //
    // [`tls_handshake(3)`](https://man.openbsd.org/tls_handshake.3)

    //
    //
    // The `read` method
    //
    // # See also
    //
    // [`tls_read(3)`](https://man.openbsd.org/tls_read.3)

    //
    //
    // The `write` method
    //
    // # See also
    //
    // [`tls_write(3)`](https://man.openbsd.org/tls_write.3)

    //
    //
    // The `close` method
    //
    // # See also
    //
    // [`tls_close(3)`](https://man.openbsd.org/tls_close.3)

    //
    //
    // The `peer_cert_provided` method
    //
    // # See also
    //
    // [`tls_peer_cert_provided(3)`](https://man.openbsd.org/tls_peer_cert_provided.3)

    //
    //
    // The `peer_cert_contains_name` method
    //
    // # See also
    //
    // [`tls_peer_cert_contains_name(3)`](https://man.openbsd.org/tls_peer_cert_contains_name.3)

    //
    //
    // The `peer_cert_hash` method
    //
    // # See also
    //
    // [`tls_peer_cert_hash(3)`](https://man.openbsd.org/tls_peer_cert_hash.3)

    //
    //
    // The `peer_cert_issuer` method
    //
    // # See also
    //
    // [`tls_peer_cert_issuer(3)`](https://man.openbsd.org/tls_peer_cert_issuer.3)

    //
    //
    // The `peer_cert_subject` method
    //
    // # See also
    //
    // [`tls_peer_cert_subject(3)`](https://man.openbsd.org/tls_peer_cert_subject.3)

    //
    //
    // The `peer_cert_notbefore` method
    //
    // # See also
    //
    // [`tls_peer_cert_notbefore(3)`](https://man.openbsd.org/tls_peer_cert_notbefore.3)

    //
    //
    // The `peer_cert_notafter` method
    //
    // # See also
    //
    // [`tls_peer_cert_notafter(3)`](https://man.openbsd.org/tls_peer_cert_notafter.3)

    //
    //
    // The `peer_cert_chain_pem` method
    //
    // # See also
    //
    // [`tls_peer_cert_chain_pem(3)`](https://man.openbsd.org/tls_peer_cert_chain_pem.3)

    //
    //
    // The `conn_alpn_selected` method
    //
    // # See also
    //
    // [`tls_conn_alpn_selected(3)`](https://man.openbsd.org/tls_conn_alpn_selected.3)

    //
    //
    // The `conn_cipher` method
    //
    // # See also
    //
    // [`tls_conn_cipher(3)`](https://man.openbsd.org/tls_conn_cipher.3)

    //
    //
    // The `conn_servername` method
    //
    // # See also
    //
    // [`tls_conn_servername(3)`](https://man.openbsd.org/tls_conn_servername.3)

    //
    //
    // The `conn_session_resumed` method
    //
    // # See also
    //
    // [`tls_conn_session_resumed(3)`](https://man.openbsd.org/tls_conn_session_resumed.3)

    //
    //
    // The `conn_version` method
    //
    // # See also
    //
    // [`tls_conn_version(3)`](https://man.openbsd.org/tls_conn_version.3)

    //
    //
    // The `ocsp_process_response` method
    //
    // # See also
    //
    // [`tls_ocsp_process_response(3)`](https://man.openbsd.org/tls_ocsp_process_response.3)

    //
    //
    // The `peer_ocsp_cert_status` method
    //
    // # See also
    //
    // [`tls_peer_ocsp_cert_status(3)`](https://man.openbsd.org/tls_peer_ocsp_cert_status.3)

    //
    //
    // The `peer_ocsp_crl_reason` method
    //
    // # See also
    //
    // [`tls_peer_ocsp_crl_reason(3)`](https://man.openbsd.org/tls_peer_ocsp_crl_reason.3)

    //
    //
    // The `peer_ocsp_next_update` method
    //
    // # See also
    //
    // [`tls_peer_ocsp_next_update(3)`](https://man.openbsd.org/tls_peer_ocsp_next_update.3)

    //
    //
    // The `peer_ocsp_response_status` method
    //
    // # See also
    //
    // [`tls_peer_ocsp_response_status(3)`](https://man.openbsd.org/tls_peer_ocsp_response_status.3)

    //
    //
    // The `peer_ocsp_result` method
    //
    // # See also
    //
    // [`tls_peer_ocsp_result(3)`](https://man.openbsd.org/tls_peer_ocsp_result.3)

    //
    //
    // The `peer_ocsp_revocation_time` method
    //
    // # See also
    //
    // [`tls_peer_ocsp_revocation_time(3)`](https://man.openbsd.org/tls_peer_ocsp_revocation_time.3)

    //
    //
    // The `peer_ocsp_this_update` method
    //
    // # See also
    //
    // [`tls_peer_ocsp_this_update(3)`](https://man.openbsd.org/tls_peer_ocsp_this_update.3)

    //
    //
    // The `peer_ocsp_url` method
    //
    // # See also
    //
    // [`tls_peer_ocsp_url(3)`](https://man.openbsd.org/tls_peer_ocsp_url.3)
}

impl error::LastError for Tls {
    /// Returns the last error of the TLS context.
    ///
    /// The `last_error` method returns an error if no error occurred with
    /// the TLS context during or since the last call to `handshake`,
    /// `read`, `write`, `close`, or `reset` involving the context,
    /// or if memory allocation failed while trying to assemble the string
    /// describing the most recent error related to the context.
    ///
    /// # See also
    ///
    /// [`tls_error(3)`](https://man.openbsd.org/tls_error.3)
    fn last_error(&self) -> error::Result<String> {
        unsafe { cvt_no_error(libtls::tls_error(self.0)) }
    }

    fn to_error(errstr: String) -> error::Result<()> {
        Err(error::TlsError::CtxError(errstr))
    }
}

impl From<*mut libtls::tls> for Tls {
    fn from(tls: *mut libtls::tls) -> Self {
        if tls.is_null() {
            panic!(io::Error::last_os_error())
        }
        Tls(tls)
    }
}

impl Drop for Tls {
    /// The `drop` method frees the [`Tls`] context and forcibly closes
    /// the connection.
    ///
    /// Please note that it calls both [`tls_close(3)`] and [`tls_free(3)`]
    /// internally to avoid leaking the internal socket file descriptor.
    /// `libtls` itself does not close the socket when calling [`tls_free(3)`]
    /// and requires the program to call [`tls_close(3)`] itself but
    /// this would be unsafe in Rust when applied to the [`Drop`] trait.
    ///
    /// # See also
    ///
    /// [`tls_close(3)`],
    /// [`tls_free(3)`]
    ///
    /// [`Drop`]: https://doc.rust-lang.org/std/ops/trait.Drop.html
    /// [`Tls`]: ../tls/struct.Tls.html
    /// [`tls_free(3)`]: https://man.openbsd.org/tls_free.3
    /// [`tls_close(3)`]: https://man.openbsd.org/tls_close.3
    fn drop(&mut self) {
        unsafe {
            // XXX Make sure that the underlying fd is not leaked.
            // XXX libtls doesn't close the socket in tls_free(3), but
            // XXX this wouldn't satisfy the safety rules of Rust.
            loop {
                let ret = libtls::tls_close(self.0);
                if !(ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) {
                    break;
                }
            }
            libtls::tls_free(self.0);
        };
    }
}

unsafe impl Send for Tls {}
unsafe impl Sync for Tls {}

/// Read callback for [`Tls::accept_cbs`] and [`Tls::connect_cbs`].
///
/// [`Tls::accept_cbs`]: struct.Tls.html#method.accept_cbs
/// [`Tls::connect_cbs`]: struct.Tls.html#method.connect_cbs
pub type TlsReadCb = libtls::tls_read_cb;

/// Write callback for [`Tls::accept_cbs`] and [`Tls::connect_cbs`].
///
/// [`Tls::accept_cbs`]: struct.Tls.html#method.accept_cbs
/// [`Tls::connect_cbs`]: struct.Tls.html#method.connect_cbs
pub type TlsWriteCb = libtls::tls_write_cb;
