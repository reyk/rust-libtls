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
use std::os::unix::io::{IntoRawFd, RawFd};
use std::time::SystemTime;

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
pub struct Tls(*mut libtls::tls, Option<RawFd>);

impl Tls {
    fn new(f: unsafe extern "C" fn() -> *mut libtls::tls) -> io::Result<Self> {
        let tls = unsafe { f() };
        if tls.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Tls(tls, None))
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

    /// Configure the TLS context.
    ///
    /// The `configure` method configures a TLS connection.  The
    /// same [`TlsConfig`] object can be used to configure multiple
    /// contexts.
    ///
    /// # See also
    ///
    /// [`tls_configure(3)`](https://man.openbsd.org/tls_configure.3)
    ///
    /// [`TlsConfig`]: ../config/struct.TlsConfig.html
    pub fn configure(&mut self, config: &TlsConfig) -> Result<()> {
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
    /// [`accept_io`](#method.accept_io)
    /// [`tls_accept_socket(3)`](https://man.openbsd.org/tls_accept_socket.3)
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
    /// The `accept_io` method can accept a new client connection on an
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
    pub fn accept_io<T>(&mut self, raw_fd: T) -> Result<Tls>
    where
        T: IntoRawFd,
    {
        // Store fd to close it automatically when dropping the object
        self.1 = Some(raw_fd.into_raw_fd());
        self.accept_socket(self.1.unwrap())
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
    /// The `connect_io` method can upgrade a connection to TLS on an
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
    pub fn connect_io<T>(&mut self, raw_fd: T, servername: &str) -> Result<()>
    where
        T: IntoRawFd,
    {
        // Store fd to close it automatically when dropping the object
        self.1 = Some(raw_fd.into_raw_fd());
        self.connect_socket(self.1.unwrap(), servername)
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

    /// Explicitly perform the TLS handshake.
    ///
    /// The `handshake` method explicitly performs the TLS handshake.  It is only
    /// necessary to call this method if you need to guarantee that the
    /// handshake has completed, as both [`read`] and [`write`] automatically
    /// perform the TLS handshake when necessary.
    ///
    /// The [`read`], [`write`], `handshake`, and [`close`] methods return
    /// -1 on error and also have two special return values:
    ///
    /// * [`TLS_WANT_POLLIN`]: The underlying read file descriptor needs to be
    ///   readable in order to continue.
    /// * [`TLS_WANT_POLLOUT`]: The underlying write file descriptor needs to be
    ///   writeable in order to continue.
    ///
    /// In the case of blocking file descriptors, the same function call should
    /// be repeated immediately.  In the case of non-blocking file descriptors,
    /// the same function call should be repeated when the required condition has
    /// been met.
    ///
    /// On success, the [`read`] and [`write`] methods return a size and
    /// the `handshake` and [`close`] methods return 0.
    ///
    /// # See also
    ///
    /// [`tls_handshake(3)`](https://man.openbsd.org/tls_handshake.3)
    ///
    /// [`read`]: #method.read
    /// [`write`]: #method.write
    /// [`close`]: #method.close
    /// [`TLS_WANT_POLLIN`]: ../constant.TLS_WANT_POLLIN.html
    /// [`TLS_WANT_POLLOUT`]: ../constant.TLS_WANT_POLLOUT.html
    pub fn handshake(&mut self) -> error::Result<isize> {
        cvt_err(self, unsafe { libtls::tls_handshake(self.0) as isize })
    }

    /// Read bytes from the TLS connection.
    ///
    /// The `read` method reads bytes of data from the connection into `buf`.  It
    /// returns the amount of data read or an error as described in [`handshake`].
    ///
    /// # See also
    ///
    /// [`handshake`],
    /// [`tls_read(3)`](https://man.openbsd.org/tls_read.3)
    ///
    /// [`handshake`]: #method.handshake
    pub fn read(&mut self, buf: &mut [u8]) -> error::Result<isize> {
        cvt_err(self, unsafe {
            libtls::tls_read(self.0, buf.as_mut_ptr() as *mut c_void, buf.len())
        })
    }

    /// Write bytes to the TLS connection.
    ///
    /// The `write` method writes bytes of data from `buf` to connection.  It
    /// returns the amount of data written or an error as described in [`handshake`].
    ///
    /// # See also
    ///
    /// [`handshake`],
    /// [`tls_write(3)`](https://man.openbsd.org/tls_write.3)
    ///
    /// [`handshake`]: #method.handshake
    pub fn write(&mut self, buf: &[u8]) -> error::Result<isize> {
        cvt_err(self, unsafe {
            libtls::tls_write(self.0, buf.as_ptr() as *const c_void, buf.len())
        })
    }

    /// Close the connection.
    ///
    /// The `close` method closes a connection after use.  Only the TLS layer will be
    /// shut down and __the caller is responsible for closing the file descriptors,
    /// unless the connection was established using [`connect`] or
    /// [`connect_servername`]__.
    ///
    /// It returns 0 on success or an error as decribed in [`handshake`].
    ///
    /// # See also
    ///
    /// [`handshake`],
    /// [`tls_write(3)`](https://man.openbsd.org/tls_write.3)
    ///
    /// [`handshake`]: #method.handshake
    /// [`connect`]: #method.connect
    /// [`connect_servername`]: #method.connect_servername
    pub fn close(&mut self) -> error::Result<isize> {
        cvt_err(self, unsafe { libtls::tls_close(self.0) as isize })
    }

    /// Check for peer certificate.
    ///
    /// The `peer_cert_provided` methods checks if the peer has provided a
    /// certificate.
    ///
    /// # See also
    ///
    /// [`tls_peer_cert_provided(3)`](https://man.openbsd.org/tls_peer_cert_provided.3)
    pub fn peer_cert_provided(&mut self) -> bool {
        unsafe { libtls::tls_peer_cert_provided(self.0) != 0 }
    }

    /// Check if the peer certificate includes a matching name.
    ///
    /// The `peer_cert_contains_name` method checks if the peer has
    /// provided a certificate that contains a SAN or CN that matches name.
    ///
    /// # See also
    ///
    /// [`tls_peer_cert_contains_name(3)`](https://man.openbsd.org/tls_peer_cert_contains_name.3)
    pub fn peer_cert_contains_name(&mut self, name: &str) -> Result<bool> {
        unsafe {
            let c_name = CString::new(name)?;
            Ok(libtls::tls_peer_cert_contains_name(self.0, c_name.as_ptr()) != 0)
        }
    }

    /// Return hash of the peer certificate.
    ///
    /// The `peer_cert_hash` method returns a string corresponding to a hash
    /// of the raw peer certificate prefixed by a hash name followed by a colon.
    /// The hash currently used is SHA256, though this could change in the
    /// future.
    ///
    /// The hash string for a certificate in file `mycert.crt` can be
    /// generated using the commands:
    ///
    /// ```sh
    /// h=$(openssl x509 -outform der -in mycert.crt | sha256)
    /// printf "SHA256:${h}\n"
    /// ```
    ///
    /// # See also
    ///
    /// [`tls_peer_cert_hash(3)`](https://man.openbsd.org/tls_peer_cert_hash.3)
    pub fn peer_cert_hash(&mut self) -> error::Result<String> {
        unsafe { cvt_string(self, libtls::tls_peer_cert_hash(self.0)) }
    }

    /// Return the issuer of the peer certificate.
    ///
    /// The `peer_cert_issuer` method returns a string corresponding to the issuer of
    /// the peer certificate.
    ///
    /// # See also
    ///
    /// [`tls_peer_cert_issuer(3)`](https://man.openbsd.org/tls_peer_cert_issuer.3)
    pub fn peer_cert_issuer(&mut self) -> error::Result<String> {
        unsafe { cvt_string(self, libtls::tls_peer_cert_issuer(self.0)) }
    }

    /// Return the subject of the peer certificate.
    ///
    /// The `peer_cert_subject` method returns a string corresponding to the subject of
    /// the peer certificate.
    ///
    /// # See also
    ///
    /// [`tls_peer_cert_subject(3)`](https://man.openbsd.org/tls_peer_cert_subject.3)
    pub fn peer_cert_subject(&mut self) -> error::Result<String> {
        unsafe { cvt_string(self, libtls::tls_peer_cert_subject(self.0)) }
    }

    /// Return the start of the validity period of the peer certififcate.
    ///
    /// The `peer_cert_notbefore` method returns the time corresponding to the start of
    /// the validity period of the peer certificate.
    ///
    /// # See also
    ///
    /// [`tls_peer_cert_notbefore(3)`](https://man.openbsd.org/tls_peer_cert_notbefore.3)
    pub fn peer_cert_notbefore(&mut self) -> error::Result<SystemTime> {
        cvt_time(self, unsafe { libtls::tls_peer_cert_notbefore(self.0) })
    }

    /// Return the end of the validity period of the peer certififcate.
    ///
    /// The `peer_cert_notafter` method returns the time corresponding to the end of
    /// the validity period of the peer certificate.
    ///
    /// The `peer_cert_notafter` method
    ///
    /// # See also
    ///
    /// [`tls_peer_cert_notafter(3)`](https://man.openbsd.org/tls_peer_cert_notafter.3)
    pub fn peer_cert_notafter(&mut self) -> error::Result<SystemTime> {
        cvt_time(self, unsafe { libtls::tls_peer_cert_notafter(self.0) })
    }

    ///
    ///
    /// The `peer_cert_chain_pem` method
    ///
    /// # See also
    ///
    /// [`tls_peer_cert_chain_pem(3)`](https://man.openbsd.org/tls_peer_cert_chain_pem.3)

    ///
    ///
    /// The `conn_alpn_selected` method
    ///
    /// # See also
    ///
    /// [`tls_conn_alpn_selected(3)`](https://man.openbsd.org/tls_conn_alpn_selected.3)
    pub fn tls_conn_alpn_selected(&mut self) -> error::Result<String> {
        unsafe { cvt_string(self, libtls::tls_conn_alpn_selected(self.0)) }
    }

    ///
    ///
    /// The `conn_cipher` method
    ///
    /// # See also
    ///
    /// [`tls_conn_cipher(3)`](https://man.openbsd.org/tls_conn_cipher.3)
    pub fn conn_cipher(&mut self) -> error::Result<String> {
        unsafe { cvt_string(self, libtls::tls_conn_cipher(self.0)) }
    }

    ///
    ///
    /// The `conn_servername` method
    ///
    /// # See also
    ///
    /// [`tls_conn_servername(3)`](https://man.openbsd.org/tls_conn_servername.3)
    pub fn conn_servername(&mut self) -> error::Result<String> {
        unsafe { cvt_string(self, libtls::tls_conn_servername(self.0)) }
    }

    ///
    ///
    /// The `conn_session_resumed` method
    ///
    /// # See also
    ///
    /// [`tls_conn_session_resumed(3)`](https://man.openbsd.org/tls_conn_session_resumed.3)
    pub fn conn_session_resumed(&mut self) -> bool {
        unsafe { libtls::tls_conn_session_resumed(self.0) != 0 }
    }

    ///
    ///
    /// The `conn_version` method
    ///
    /// # See also
    ///
    /// [`tls_conn_version(3)`](https://man.openbsd.org/tls_conn_version.3)
    pub fn conn_version(&mut self) -> error::Result<String> {
        unsafe { cvt_string(self, libtls::tls_conn_version(self.0)) }
    }

    ///
    ///
    /// The `ocsp_process_response` method
    ///
    /// # See also
    ///
    /// [`tls_ocsp_process_response(3)`](https://man.openbsd.org/tls_ocsp_process_response.3)
    pub fn ocsp_process_response(&mut self, response: &[u8]) -> error::Result<()> {
        cvt(self, unsafe {
            libtls::tls_ocsp_process_response(self.0, response.as_ptr(), response.len())
        })
    }

    ///
    ///
    /// The `peer_ocsp_cert_status` method
    ///
    /// # See also
    ///
    /// [`tls_peer_ocsp_cert_status(3)`](https://man.openbsd.org/tls_peer_ocsp_cert_status.3)
    pub fn peer_ocsp_cert_status(&mut self) -> error::Result<isize> {
        cvt_err(self, unsafe {
            libtls::tls_peer_ocsp_cert_status(self.0) as isize
        })
    }

    ///
    ///
    /// The `peer_ocsp_crl_reason` method
    ///
    /// # See also
    ///
    /// [`tls_peer_ocsp_crl_reason(3)`](https://man.openbsd.org/tls_peer_ocsp_crl_reason.3)
    pub fn peer_ocsp_crl_reason(&mut self) -> error::Result<isize> {
        cvt_err(self, unsafe {
            libtls::tls_peer_ocsp_crl_reason(self.0) as isize
        })
    }

    ///
    ///
    /// The `peer_ocsp_next_update` method
    ///
    /// # See also
    ///
    /// [`tls_peer_ocsp_next_update(3)`](https://man.openbsd.org/tls_peer_ocsp_next_update.3)
    pub fn peer_ocsp_next_update(&mut self) -> error::Result<SystemTime> {
        cvt_time(self, unsafe { libtls::tls_peer_ocsp_next_update(self.0) })
    }

    ///
    ///
    /// The `peer_ocsp_response_status` method
    ///
    /// # See also
    ///
    /// [`tls_peer_ocsp_response_status(3)`](https://man.openbsd.org/tls_peer_ocsp_response_status.3)
    pub fn peer_ocsp_response_status(&mut self) -> error::Result<isize> {
        cvt_err(self, unsafe {
            libtls::tls_peer_ocsp_response_status(self.0) as isize
        })
    }

    ///
    ///
    /// The `peer_ocsp_result` method
    ///
    /// # See also
    ///
    /// [`tls_peer_ocsp_result(3)`](https://man.openbsd.org/tls_peer_ocsp_result.3)
    pub fn peer_ocsp_result(&mut self) -> error::Result<String> {
        unsafe { cvt_string(self, libtls::tls_peer_ocsp_result(self.0)) }
    }

    ///
    ///
    /// The `peer_ocsp_revocation_time` method
    ///
    /// # See also
    ///
    /// [`tls_peer_ocsp_revocation_time(3)`](https://man.openbsd.org/tls_peer_ocsp_revocation_time.3)
    pub fn peer_ocsp_revocation_time(&mut self) -> error::Result<SystemTime> {
        cvt_time(self, unsafe {
            libtls::tls_peer_ocsp_revocation_time(self.0)
        })
    }

    ///
    ///
    /// The `peer_ocsp_this_update` method
    ///
    /// # See also
    ///
    /// [`tls_peer_ocsp_this_update(3)`](https://man.openbsd.org/tls_peer_ocsp_this_update.3)
    pub fn peer_ocsp_this_update(&mut self) -> error::Result<SystemTime> {
        cvt_time(self, unsafe { libtls::tls_peer_ocsp_this_update(self.0) })
    }

    ///
    ///
    /// The `peer_ocsp_url` method
    ///
    /// # See also
    ///
    /// [`tls_peer_ocsp_url(3)`](https://man.openbsd.org/tls_peer_ocsp_url.3)
    pub fn peer_ocsp_url(&mut self) -> error::Result<String> {
        unsafe { cvt_string(self, libtls::tls_peer_ocsp_url(self.0)) }
    }
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
        Tls(tls, None)
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
            if let Some(fd) = self.1 {
                libtls::close(fd);
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
