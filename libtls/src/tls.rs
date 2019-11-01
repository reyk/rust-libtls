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

use std::ffi::CString;
use std::io;
use std::net::ToSocketAddrs;
use std::os::raw::c_void;
use std::time::SystemTime;

#[cfg(unix)]
use std::os::unix::io::{IntoRawFd, RawFd};

use super::config::TlsConfig;
use super::error::{LastError, Result};
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

    /// Accept a new TLS connection on a pair of existing file descriptors.
    ///
    /// The `accept_fds` method can accept a new client connection on a pair
    /// of existing file descriptors.
    ///
    /// # See also
    ///
    /// [`tls_accept_fds(3)`](https://man.openbsd.org/tls_accept_fds.3)
    #[cfg(unix)]
    pub fn accept_fds(&mut self, fd_read: RawFd, fd_write: RawFd) -> Result<Tls> {
        unsafe {
            // XXX Make sure that this pointer handling is correct!
            let mut cctx: *mut libtls::tls = std::ptr::null_mut();
            cvt(
                self,
                libtls::tls_accept_fds(self.0, &mut cctx, fd_read, fd_write),
            )?;
            Ok(cctx.into())
        }
    }

    /// Accept a new TLS connection on a socket.
    ///
    /// The `accept_socket` method can accept a new client
    /// connection on an already established
    /// socket connection.
    ///
    /// # See also
    ///
    /// [`accept_raw_fd`](#method.accept_raw_fd)
    /// [`tls_accept_socket(3)`](https://man.openbsd.org/tls_accept_socket.3)
    #[cfg(unix)]
    pub fn accept_socket(&mut self, socket: RawFd) -> Result<Tls> {
        unsafe {
            // XXX Make sure that this pointer handling is correct!
            let mut cctx: *mut libtls::tls = std::ptr::null_mut();
            cvt(self, libtls::tls_accept_socket(self.0, &mut cctx, socket))?;
            Ok(cctx.into())
        }
    }

    /// Accept a new TLS connection on an established connection.
    ///
    /// The `accept_raw_fd` method can accept a new client connection on an
    /// already established connection that implements the [`IntoRawFd`] trait,
    /// e.g. [`TcpStream`].
    /// It is a wrapper function on top of [`accept_socket`].
    ///
    /// # See also
    ///
    /// [`accept_socket`]
    ///
    /// [`accept_socket`]: #method.accept_socket
    /// [`TcpStream`]: https://doc.rust-lang.org/std/net/TcpStream.html
    /// [`IntoRawFd`]: https://doc.rust-lang.org/std/os/unix/io/IntoRawFd.html
    #[cfg(unix)]
    pub fn accept_raw_fd<T>(&mut self, raw_fd: T) -> Result<Tls>
    where
        T: IntoRawFd,
    {
        self.accept_socket(raw_fd.into_raw_fd())
    }

    /// Accept a new TLS connection with custom I/O callbacks.
    ///
    /// The `accept_cbs` method allows read and write callback functions to
    /// handle data transfers.  The specified `cb_arg` parameter is passed back to
    /// the functions, and can contain a pointer to any caller-specified data.
    ///
    /// # See also
    ///
    /// [`tls_accept_cbs(3)`](https://man.openbsd.org/tls_accept_cbs.3)
    pub unsafe fn accept_cbs(
        &mut self,
        read_cb: TlsReadCb,
        write_cb: TlsWriteCb,
        cb_arg: Option<*mut c_void>,
    ) -> Result<Tls> {
        // XXX Make sure that this pointer handling is correct!
        let mut cctx: *mut libtls::tls = std::ptr::null_mut();
        let cb_arg = cb_arg.unwrap_or(std::ptr::null_mut());
        cvt(
            self,
            libtls::tls_accept_cbs(self.0, &mut cctx, read_cb, write_cb, cb_arg),
        )?;
        Ok(cctx.into())
    }

    /// Initiate a new TLS connection.
    ///
    /// The `connect` method initiates a new client connection on a
    /// [`Tls`] object that has been configured with [`configure`].
    /// This method will create a new socket, connect to the specified host and port,
    /// and then establish a secure connection.  The port may be numeric or a
    /// service name.  If it is None, then a host of the format "hostname:port"
    /// is permitted.  The name to use for verification is inferred from the host value.
    ///
    /// # See also
    ///
    /// [`tls_connect(3)`](https://man.openbsd.org/tls_connect.3)
    ///
    /// [`Tls`]: struct.Tls.html
    /// [`configure`]: #method.configure
    pub fn connect(&mut self, host: &str, port: Option<&str>) -> Result<()> {
        unsafe {
            let c_host = CString::new(host)?;
            let c_port = match port {
                Some(port) => {
                    let c_port = CString::new(port)?;
                    c_port.as_ptr()
                }
                None => std::ptr::null(),
            };
            cvt(self, libtls::tls_connect(self.0, c_host.as_ptr(), c_port))
        }
    }

    /// Initiate a new TLS connection over a pair of existing file descriptors.
    ///
    /// The `connect_fds` method is a variant of [`connect`] that
    /// establishes a secure connection over a pair of existing file
    /// descriptors.  The `servername` argument is used for verification of
    /// the TLS server name.
    ///
    /// # See also
    ///
    /// [`tls_connect_fds(3)`](https://man.openbsd.org/tls_connect_fds.3)
    ///
    /// [`connect`]: #method.connect
    #[cfg(unix)]
    pub fn connect_fds(&mut self, fd_read: RawFd, fd_write: RawFd, servername: &str) -> Result<()> {
        unsafe {
            let c_servername = CString::new(servername)?;
            cvt(
                self,
                libtls::tls_connect_fds(self.0, fd_read, fd_write, c_servername.as_ptr()),
            )
        }
    }

    /// Initiate a new TLS connection with a specified server name.
    ///
    /// The `connect_servername` method has the same behaviour as [`connect`],
    /// however the name to use for verification is explicitly provided,
    /// for the case where the TLS server name differs from the DNS name.
    ///
    /// # See also
    ///
    /// [`tls_connect_servername(3)`](https://man.openbsd.org/tls_connect_servername.3)
    ///
    /// [`connect`]: #method.connect
    pub fn connect_servername<A: ToSocketAddrs>(
        &mut self,
        host: A,
        servername: &str,
    ) -> Result<()> {
        let mut addr_iter = host.to_socket_addrs()?;

        // Get the first address in the list (only one is supported)
        let addr = match addr_iter.next() {
            None => return Self::to_error("no address to connect to".to_owned()),
            Some(addr) => addr,
        };

        unsafe {
            let c_host = CString::new(addr.to_string())?;
            let c_servername = CString::new(servername)?;
            cvt(
                self,
                libtls::tls_connect_servername(
                    self.0,
                    c_host.as_ptr(),
                    std::ptr::null(),
                    c_servername.as_ptr(),
                ),
            )
        }
    }

    /// Initiate a new TLS connection over an established socket.
    ///
    /// The `connect_socket` method is a variant of [`connect_servername`] that
    /// can upgrade an already existing socket to TLS.
    ///
    /// # See also
    ///
    /// [`tls_connect_socket(3)`](https://man.openbsd.org/tls_connect_socket.3)
    ///
    /// [`connect_servername`]: #method.connect_servername
    #[cfg(unix)]
    pub fn connect_socket(&mut self, socket: RawFd, servername: &str) -> Result<()> {
        unsafe {
            let c_servername = CString::new(servername)?;
            cvt(
                self,
                libtls::tls_connect_socket(self.0, socket, c_servername.as_ptr()),
            )
        }
    }

    /// Initiate a new TLS connection over an established connection.
    ///
    /// The `connect_raw_fd` method can upgrade a connection to TLS on an
    /// already established connection that implements the [`IntoRawFd`] trait,
    /// e.g. [`TcpStream`].
    /// It is a wrapper function on top of [`connect_socket`].
    ///
    /// # See also
    ///
    /// [`connect_socket`]
    ///
    /// [`connect_socket`]: #method.connect_socket
    /// [`TcpStream`]: https://doc.rust-lang.org/std/net/TcpStream.html
    /// [`IntoRawFd`]: https://doc.rust-lang.org/std/os/unix/io/IntoRawFd.html
    #[cfg(unix)]
    pub fn connect_raw_fd<T>(&mut self, raw_fd: T, servername: &str) -> Result<()>
    where
        T: IntoRawFd,
    {
        self.connect_socket(raw_fd.into_raw_fd(), servername)
    }

    /// Initiate a new TLS connection with custom I/O callbacks.
    ///
    /// The `connect_cbs` method allows read and write callback functions to
    /// handle data transfers.  The specified `cb_arg` parameter is passed back to
    /// the functions, and can contain a pointer to any caller-specified data.
    /// The `servername` is used to validate the TLS server name.
    ///
    /// # See also
    ///
    /// [`tls_connect_cbs(3)`](https://man.openbsd.org/tls_connect_cbs.3)
    pub unsafe fn connect_cbs(
        &mut self,
        read_cb: TlsReadCb,
        write_cb: TlsWriteCb,
        cb_arg: Option<*mut c_void>,
        servername: &str,
    ) -> Result<()> {
        // XXX Make sure that this pointer handling is correct!
        let c_servername = CString::new(servername)?;
        let cb_arg = cb_arg.unwrap_or(std::ptr::null_mut());
        cvt(
            self,
            libtls::tls_connect_cbs(self.0, read_cb, write_cb, cb_arg, c_servername.as_ptr()),
        )
    }

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
    pub fn close(&mut self) -> error::Result<()> {
        cvt(self, unsafe { libtls::tls_close(self.0) })
    }

    //
    //
    // The `peer_cert_provided` method
    //
    // # See also
    //
    // [`tls_peer_cert_provided(3)`](https://man.openbsd.org/tls_peer_cert_provided.3)
    pub fn peer_cert_provided(&mut self) -> error::Result<()> {
        cvt(self, unsafe { libtls::tls_peer_cert_provided(self.0) })
    }

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
    pub fn peer_cert_notbefore(&mut self) -> error::Result<SystemTime> {
        cvt_time(self, unsafe { libtls::tls_peer_cert_notbefore(self.0) })
    }

    //
    //
    // The `peer_cert_notafter` method
    //
    // # See also
    //
    // [`tls_peer_cert_notafter(3)`](https://man.openbsd.org/tls_peer_cert_notafter.3)
    pub fn peer_cert_notafter(&mut self) -> error::Result<SystemTime> {
        cvt_time(self, unsafe { libtls::tls_peer_cert_notafter(self.0) })
    }

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
    pub fn conn_session_resumed(&mut self) -> error::Result<()> {
        cvt(self, unsafe { libtls::tls_conn_session_resumed(self.0) })
    }

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
    pub fn peer_ocsp_cert_status(&mut self) -> error::Result<()> {
        cvt(self, unsafe { libtls::tls_peer_ocsp_cert_status(self.0) })
    }

    //
    //
    // The `peer_ocsp_crl_reason` method
    //
    // # See also
    //
    // [`tls_peer_ocsp_crl_reason(3)`](https://man.openbsd.org/tls_peer_ocsp_crl_reason.3)
    pub fn peer_ocsp_crl_reason(&mut self) -> error::Result<()> {
        cvt(self, unsafe { libtls::tls_peer_ocsp_crl_reason(self.0) })
    }

    //
    //
    // The `peer_ocsp_next_update` method
    //
    // # See also
    //
    // [`tls_peer_ocsp_next_update(3)`](https://man.openbsd.org/tls_peer_ocsp_next_update.3)
    pub fn peer_ocsp_next_update(&mut self) -> error::Result<SystemTime> {
        cvt_time(self, unsafe { libtls::tls_peer_ocsp_next_update(self.0) })
    }

    //
    //
    // The `peer_ocsp_response_status` method
    //
    // # See also
    //
    // [`tls_peer_ocsp_response_status(3)`](https://man.openbsd.org/tls_peer_ocsp_response_status.3)
    pub fn peer_ocsp_response_status(&mut self) -> error::Result<()> {
        cvt(self, unsafe {
            libtls::tls_peer_ocsp_response_status(self.0)
        })
    }

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
    pub fn peer_ocsp_revocation_time(&mut self) -> error::Result<SystemTime> {
        cvt_time(self, unsafe {
            libtls::tls_peer_ocsp_revocation_time(self.0)
        })
    }

    //
    //
    // The `peer_ocsp_this_update` method
    //
    // # See also
    //
    // [`tls_peer_ocsp_this_update(3)`](https://man.openbsd.org/tls_peer_ocsp_this_update.3)
    pub fn peer_ocsp_this_update(&mut self) -> error::Result<SystemTime> {
        cvt_time(self, unsafe { libtls::tls_peer_ocsp_this_update(self.0) })
    }

    //
    //
    // The `peer_ocsp_url` method
    //
    // # See also
    //
    // [`tls_peer_ocsp_url(3)`](https://man.openbsd.org/tls_peer_ocsp_url.3)
}

impl LastError for Tls {
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

    fn to_error<T>(errstr: String) -> error::Result<T> {
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
