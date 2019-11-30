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

use crate::{
    config::TlsConfig,
    error::{LastError, Result},
    *,
};
use std::{
    ffi::{CStr, CString},
    io,
    net::ToSocketAddrs,
    os::raw::c_void,
    os::unix::io::{AsRawFd, RawFd},
    slice,
    time::SystemTime,
};

/// Convert return value of `Tls` I/O functions into `io::Error`.
///
/// This macro converts the return value of [`Tls::tls_read`], [`Tls::tls_write`],
/// [`Tls::tls_handshake`], or [`Tls::close`] into [`io::Error`].
///
/// # See also
///
/// [`Tls::tls_handshake`]
///
/// [`Tls::tls_read`]: tls/struct.Tls.html#method.tls_read
/// [`Tls::tls_write`]: tls/struct.Tls.html#method.tls_write
/// [`Tls::tls_handshake`]: tls/struct.Tls.html#method.tls_handshake
/// [`Tls::close`]: tls/struct.Tls.html#method.close
/// [`io::Error`]: https://doc.rust-lang.org/std/io/struct.Error.html
#[macro_export]
macro_rules! try_tls {
    ($self: expr, $call: expr) => {
        match $call {
            Err(err) => Err(io::Error::new(io::ErrorKind::Other, err)),
            Ok(size) => {
                if size == TLS_WANT_POLLIN as isize || size == TLS_WANT_POLLOUT as isize {
                    Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        io::Error::last_os_error(),
                    ))
                } else {
                    Ok(size as usize)
                }
            }
        }
    };
}

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
/// After use, a TLS context should be closed with [`tls_close`], which
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
/// [`tls_close`]: struct.Tls.html#method.close
/// [`reset`]: struct.Tls.html#method.reset
/// [dropped]: struct.Tls.html#impl-Drop
#[derive(Debug)]
pub struct Tls(*mut libtls_sys::tls, RawFd);

impl Tls {
    fn new(f: unsafe extern "C" fn() -> *mut libtls_sys::tls) -> io::Result<Self> {
        let tls = unsafe { f() };
        if tls.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Tls(tls, -1))
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
        Self::new(libtls_sys::tls_client)
    }

    /// Create a new TLS server.
    ///
    /// The `server` is used to accept connections in TLS server programs.
    ///
    /// # See also
    ///
    /// [`tls_server(3)`](https://man.openbsd.org/tls_server.3)
    pub fn server() -> io::Result<Self> {
        Self::new(libtls_sys::tls_server)
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
        cvt(self, unsafe { libtls_sys::tls_configure(self.0, config.0) })
    }

    /// Wrap a raw C `tls` object.
    ///
    /// # Safety
    ///
    /// This function assumes that the raw pointer is valid, and takes
    /// ownership of the libtls object.
    /// Do not call `tls_free` yourself, since the `drop` destructor will
    /// take care of it.
    ///
    /// # Panics
    ///
    /// Panics if `tls` is a null pointer.
    pub unsafe fn from_sys(tls: *mut libtls_sys::tls) -> Self {
        if tls.is_null() {
            panic!(io::Error::last_os_error())
        }
        Tls(tls, -1)
    }

    /// Reset the TLS connection.
    ///
    /// A TLS context can be `reset`, allowing for it to be reused.
    ///
    /// # See also
    ///
    /// [`tls_reset(3)`](https://man.openbsd.org/tls_reset.3)
    pub fn reset(&mut self) {
        unsafe { libtls_sys::tls_reset(self.0) };
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
        let mut tls = Self::client()?;
        unsafe {
            cvt(
                self,
                libtls_sys::tls_accept_fds(self.0, &mut tls.0, fd_read, fd_write),
            )?;
        }
        Ok(tls)
    }

    /// Accept a new TLS connection on a socket.
    ///
    /// The `accept_socket` method can accept a new client
    /// connection on an already established
    /// socket connection.
    /// The socket `RawFd` is not closed after dropping the object.
    ///
    /// # See also
    ///
    /// [`accept_io`](#method.accept_io)
    /// [`tls_accept_socket(3)`](https://man.openbsd.org/tls_accept_socket.3)
    pub fn accept_socket(&mut self, socket: RawFd) -> Result<Tls> {
        let mut tls = Self::client()?;
        unsafe {
            cvt(
                self,
                libtls_sys::tls_accept_socket(self.0, &mut tls.0, socket),
            )?;
            self.1 = socket;
        }
        Ok(tls)
    }

    /// Accept a new TLS connection on an established connection.
    ///
    /// The `accept_raw_fd` method can accept a new client connection on an
    /// already established connection that implements the [`AsRawFd`] trait,
    /// e.g. [`TcpStream`].
    /// It is a wrapper function on top of [`accept_socket`].
    ///
    /// # See also
    ///
    /// [`accept_socket`]
    ///
    /// [`accept_socket`]: #method.accept_socket
    /// [`TcpStream`]: https://doc.rust-lang.org/std/net/TcpStream.html
    /// [`AsRawFd`]: https://doc.rust-lang.org/std/os/unix/io/AsRawFd.html
    pub fn accept_raw_fd<T>(&mut self, raw_fd: &T) -> Result<Tls>
    where
        T: AsRawFd,
    {
        self.accept_socket(raw_fd.as_raw_fd())
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
        let mut tls = Self::client()?;
        let cb_arg = cb_arg.unwrap_or(std::ptr::null_mut());
        cvt(
            self,
            libtls_sys::tls_accept_cbs(self.0, &mut tls.0, read_cb, write_cb, cb_arg),
        )?;
        Ok(tls)
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
            let res = match port {
                Some(val) => {
                    let c_port = CString::new(val)?;
                    libtls_sys::tls_connect(self.0, c_host.as_ptr(), c_port.as_ptr())
                }
                None => libtls_sys::tls_connect(self.0, c_host.as_ptr(), std::ptr::null()),
            };
            cvt(self, res)
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
                libtls_sys::tls_connect_fds(self.0, fd_read, fd_write, c_servername.as_ptr()),
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
        let mut last_error = Self::to_error("no address to connect to".to_owned());

        // This closure tries to open the TLS connection.
        let mut connect = |addr: &str, servername: &str| -> Result<()> {
            unsafe {
                let c_host = CString::new(addr.to_string())?;
                let c_servername = CString::new(servername)?;
                cvt(
                    self,
                    libtls_sys::tls_connect_servername(
                        self.0,
                        c_host.as_ptr(),
                        std::ptr::null(),
                        c_servername.as_ptr(),
                    ),
                )
            }
        };

        // Return on the first successful TLS connection in the list.
        for addr in host.to_socket_addrs()? {
            match connect(&addr.to_string(), servername) {
                Ok(_) => return Ok(()),
                Err(err) => last_error = Err(err),
            }
        }

        last_error
    }

    /// Initiate a new TLS connection over an established socket.
    ///
    /// The `connect_socket` method is a variant of [`connect_servername`] that
    /// can upgrade an already existing socket to TLS.
    /// The socket `RawFd` is not closed after dropping the object.
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
                libtls_sys::tls_connect_socket(self.0, socket, c_servername.as_ptr()),
            )?;
            self.1 = socket;
            Ok(())
        }
    }

    /// Initiate a new TLS connection over an established connection.
    ///
    /// The `connect_raw_fd` method can upgrade a connection to TLS on an
    /// already established connection that implements the [`AsRawFd] trait,
    /// e.g. [`TcpStream`].
    /// It is a wrapper function on top of [`connect_socket`].
    ///
    /// # See also
    ///
    /// [`connect_socket`]
    ///
    /// [`connect_socket`]: #method.connect_socket
    /// [`TcpStream`]: https://doc.rust-lang.org/std/net/TcpStream.html
    /// [`AsRawFd`]: https://doc.rust-lang.org/std/os/unix/io/AsRawFd.html
    pub fn connect_raw_fd<T>(&mut self, raw_fd: &T, servername: &str) -> Result<()>
    where
        T: AsRawFd,
    {
        self.connect_socket(raw_fd.as_raw_fd(), servername)
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
            libtls_sys::tls_connect_cbs(self.0, read_cb, write_cb, cb_arg, c_servername.as_ptr()),
        )
    }

    /// Explicitly perform the TLS handshake.
    ///
    /// The `tls_handshake` method explicitly performs the TLS handshake.  It is only
    /// necessary to call this method if you need to guarantee that the
    /// handshake has completed, as both [`tls_read`] and [`tls_write`] automatically
    /// perform the TLS handshake when necessary.
    ///
    /// The [`tls_read`], [`tls_write`], `tls_handshake`, and [`tls_close`] methods
    /// return -1 on error and also have two special return values:
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
    /// On success, the [`tls_read`] and [`tls_write`] methods return a size and
    /// the `tls_handshake` and [`tls_close`] methods return 0.
    ///
    /// # See also
    ///
    /// [`tls_handshake(3)`](https://man.openbsd.org/tls_handshake.3)
    ///
    /// [`tls_read`]: #method.tls_read
    /// [`tls_write`]: #method.tls_write
    /// [`tls_close`]: #method.close
    /// [`TLS_WANT_POLLIN`]: ../constant.TLS_WANT_POLLIN.html
    /// [`TLS_WANT_POLLOUT`]: ../constant.TLS_WANT_POLLOUT.html
    pub fn tls_handshake(&mut self) -> error::Result<isize> {
        cvt_err(self, unsafe { libtls_sys::tls_handshake(self.0) as isize })
    }

    /// Read bytes from the TLS connection.
    ///
    /// The `tls_read` method reads bytes of data from the connection into `buf`.  It
    /// returns the amount of data read or an error as described in [`tls_handshake`].
    ///
    /// This function is provided for the completeness of the API, programs should
    /// use the implemented [`read`] function of the `Read` trait instead.
    ///
    /// # See also
    ///
    /// [`tls_handshake`],
    /// [`read`],
    /// [`tls_read(3)`](https://man.openbsd.org/tls_read.3)
    ///
    /// [`read`]: #impl-Read
    /// [`tls_handshake`]: #method.tls_handshake
    pub fn tls_read(&mut self, buf: &mut [u8]) -> error::Result<isize> {
        cvt_err(self, unsafe {
            libtls_sys::tls_read(self.0, buf.as_mut_ptr() as *mut c_void, buf.len())
        })
    }

    /// Write bytes to the TLS connection.
    ///
    /// The `tls_write` method writes bytes of data from `buf` to connection.  It
    /// returns the amount of data written or an error as described in [`tls_handshake`].
    ///
    /// This function is provided for the completeness of the API, programs should
    /// use the implemented [`write`] function of the `Write` trait instead.
    ///
    /// # See also
    ///
    /// [`tls_handshake`],
    /// [`write`],
    /// [`tls_write(3)`](https://man.openbsd.org/tls_write.3)
    ///
    /// [`write`]: #impl-Write
    /// [`tls_handshake`]: #method.tls_handshake
    pub fn tls_write(&mut self, buf: &[u8]) -> error::Result<isize> {
        cvt_err(self, unsafe {
            libtls_sys::tls_write(self.0, buf.as_ptr() as *const c_void, buf.len())
        })
    }

    /// Close the TLS connection.
    ///
    /// The `tls_close` method closes a connection after use.  Only the TLS layer will be
    /// shut down and __the caller is responsible for closing the file descriptors,
    /// unless the connection was established using [`connect`] or
    /// [`connect_servername`]__.
    ///
    /// It returns 0 on success or an error as decribed in [`tls_handshake`].
    ///
    /// # See also
    ///
    /// [`tls_handshake`],
    /// [`tls_write(3)`](https://man.openbsd.org/tls_write.3)
    ///
    /// [`tls_handshake`]: #method.tls_handshake
    /// [`connect`]: #method.connect
    /// [`connect_servername`]: #method.connect_servername
    pub fn tls_close(&mut self) -> error::Result<isize> {
        cvt_err(self, unsafe { libtls_sys::tls_close(self.0) as isize })
    }

    /// Close the TLS connection.
    ///
    /// The `close` method closes a connection after use.
    /// It calls [`tls_close`] and converts the result into an `io::Error`.
    ///
    /// # See also
    ///
    /// [`tls_close`]
    ///
    /// [`tls_close`]: #method.tls_close
    pub fn close(&mut self) -> io::Result<()> {
        try_tls!(self, self.tls_close()).map(|_| ())
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
        unsafe { libtls_sys::tls_peer_cert_provided(self.0) != 0 }
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
            Ok(libtls_sys::tls_peer_cert_contains_name(self.0, c_name.as_ptr()) != 0)
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
        unsafe { cvt_string(self, libtls_sys::tls_peer_cert_hash(self.0)) }
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
        unsafe { cvt_string(self, libtls_sys::tls_peer_cert_issuer(self.0)) }
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
        unsafe { cvt_string(self, libtls_sys::tls_peer_cert_subject(self.0)) }
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
        cvt_time(self, unsafe { libtls_sys::tls_peer_cert_notbefore(self.0) })
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
        cvt_time(self, unsafe { libtls_sys::tls_peer_cert_notafter(self.0) })
    }

    /// Return the PEM-encoded peer certificate.
    ///
    /// The `peer_cert_chain_pem` method returns a vector of memory containing a PEM-
    /// encoded certificate chain for the peer certificate.
    ///
    /// # See also
    ///
    /// [`tls_peer_cert_chain_pem(3)`](https://man.openbsd.org/tls_peer_cert_chain_pem.3)
    pub fn peer_cert_chain_pem(&mut self) -> error::Result<Vec<u8>> {
        unsafe {
            let mut size = 0;
            let ptr = libtls_sys::tls_peer_cert_chain_pem(self.0, &mut size);
            if ptr.is_null() {
                let errstr = self.last_error().unwrap_or_else(|_| "no error".to_string());
                Self::to_error(errstr)
            } else {
                let data = slice::from_raw_parts(ptr, size);
                Ok(data.to_vec())
            }
        }
    }

    /// Return the selected ALPN protocol.
    ///
    /// The `conn_alpn_selected` method returns a string that specifies the ALPN
    /// protocol selected for use with the peer.  If no protocol
    /// was selected then `None` is returned.
    ///
    /// # See also
    ///
    /// [`tls_conn_alpn_selected(3)`](https://man.openbsd.org/tls_conn_alpn_selected.3)
    pub fn conn_alpn_selected(&mut self) -> Option<String> {
        unsafe {
            let ptr = libtls_sys::tls_conn_alpn_selected(self.0);
            if ptr.is_null() {
                None
            } else {
                let c_str = CStr::from_ptr(ptr);
                let string = c_str.to_owned().to_string_lossy().to_string();
                Some(string)
            }
        }
    }

    /// Return the negotiated cipher suite.
    ///
    /// The `conn_cipher` method returns a string corresponding to the cipher suite
    /// negotiated with the peer.
    ///
    /// # See also
    ///
    /// [`tls_conn_cipher(3)`](https://man.openbsd.org/tls_conn_cipher.3)
    pub fn conn_cipher(&mut self) -> error::Result<String> {
        unsafe { cvt_string(self, libtls_sys::tls_conn_cipher(self.0)) }
    }

    /// Return the client's server name.
    ///
    /// The `conn_servername` method returns a string corresponding to the `servername`
    /// that the client connected to the server requested by sending a TLS Server Name
    /// Indication extension (server only).
    ///
    /// # See also
    ///
    /// [`tls_conn_servername(3)`](https://man.openbsd.org/tls_conn_servername.3)
    pub fn conn_servername(&mut self) -> error::Result<String> {
        unsafe { cvt_string(self, libtls_sys::tls_conn_servername(self.0)) }
    }

    /// Check if a TLS session has been resumed.
    ///
    /// The `conn_session_resumed` method indicates whether a TLS session has been
    /// resumed during the handshake with the server connected to the client (client
    /// only).
    ///
    /// # See also
    ///
    /// [`tls_conn_session_resumed(3)`](https://man.openbsd.org/tls_conn_session_resumed.3)
    pub fn conn_session_resumed(&mut self) -> bool {
        unsafe { libtls_sys::tls_conn_session_resumed(self.0) != 0 }
    }

    /// Return the negotiated TLS version as a string.
    ///
    /// The `conn_version` method returns a string corresponding to a TLS version
    /// negotiated with the peer.
    ///
    /// # See also
    ///
    /// [`tls_conn_version(3)`](https://man.openbsd.org/tls_conn_version.3)
    pub fn conn_version(&mut self) -> error::Result<String> {
        unsafe { cvt_string(self, libtls_sys::tls_conn_version(self.0)) }
    }

    /// Process a raw OCSP response.
    ///
    /// The `ocsp_process_response` method processes a raw OCSP response in response of
    /// size size to check the revocation status of the peer certificate.
    /// A successful result indicates that the certificate has not been revoked.
    ///
    /// # See also
    ///
    /// [`tls_ocsp_process_response(3)`](https://man.openbsd.org/tls_ocsp_process_response.3)
    pub fn ocsp_process_response(&mut self, response: &[u8]) -> error::Result<()> {
        cvt(self, unsafe {
            libtls_sys::tls_ocsp_process_response(self.0, response.as_ptr(), response.len())
        })
    }

    /// OCSP certificate status.
    ///
    /// The `peer_ocsp_cert_status` method returns the OCSP certificate status code as
    /// per RFC 6960 section 2.2.
    ///
    /// # See also
    ///
    /// [`tls_peer_ocsp_cert_status(3)`](https://man.openbsd.org/tls_peer_ocsp_cert_status.3)
    pub fn peer_ocsp_cert_status(&mut self) -> error::Result<isize> {
        cvt_err(self, unsafe {
            libtls_sys::tls_peer_ocsp_cert_status(self.0) as isize
        })
    }

    /// OCSP certificate revocation reason.
    ///
    /// The `peer_ocsp_crl_reason` method returns the OCSP certificate revocation reason
    /// status code as per RFC 5280 section 5.3.1.
    ///
    /// # See also
    ///
    /// [`tls_peer_ocsp_crl_reason(3)`](https://man.openbsd.org/tls_peer_ocsp_crl_reason.3)
    pub fn peer_ocsp_crl_reason(&mut self) -> error::Result<isize> {
        cvt_err(self, unsafe {
            libtls_sys::tls_peer_ocsp_crl_reason(self.0) as isize
        })
    }

    /// OCSP next update time.
    ///
    /// The `peer_ocsp_next_update` method returns the OCSP next update time.
    ///
    /// # See also
    ///
    /// [`tls_peer_ocsp_next_update(3)`](https://man.openbsd.org/tls_peer_ocsp_next_update.3)
    pub fn peer_ocsp_next_update(&mut self) -> error::Result<SystemTime> {
        cvt_time(self, unsafe {
            libtls_sys::tls_peer_ocsp_next_update(self.0)
        })
    }

    /// OCSP response status.
    ///
    /// The `peer_ocsp_response_status` method returns the OCSP response status as per
    /// RFC 6960 section 2.3.
    ///
    /// # See also
    ///
    /// [`tls_peer_ocsp_response_status(3)`](https://man.openbsd.org/tls_peer_ocsp_response_status.3)
    pub fn peer_ocsp_response_status(&mut self) -> error::Result<isize> {
        cvt_err(self, unsafe {
            libtls_sys::tls_peer_ocsp_response_status(self.0) as isize
        })
    }

    /// Textual representation of the OCSP status code.
    ///
    /// The `peer_ocsp_result` method returns a textual representation of the OCSP
    /// status code returned by one of the previous three functions.  If the OCSP
    /// response was valid and the certificate was not revoked, the string
    /// indicates the OCSP certificate status.  Otherwise, the string indicates
    /// the OCSP certificate revocation reason or the OCSP error.
    ///
    /// # See also
    ///
    /// [`tls_peer_ocsp_result(3)`](https://man.openbsd.org/tls_peer_ocsp_result.3)
    pub fn peer_ocsp_result(&mut self) -> error::Result<String> {
        unsafe { cvt_string(self, libtls_sys::tls_peer_ocsp_result(self.0)) }
    }

    /// OCSP revocation time.
    ///
    /// The `peer_ocsp_revocation_time` method returns the OCSP revocation time.
    ///
    /// # See also
    ///
    /// [`tls_peer_ocsp_revocation_time(3)`](https://man.openbsd.org/tls_peer_ocsp_revocation_time.3)
    pub fn peer_ocsp_revocation_time(&mut self) -> error::Result<SystemTime> {
        cvt_time(self, unsafe {
            libtls_sys::tls_peer_ocsp_revocation_time(self.0)
        })
    }

    /// OCSP this update time.
    ///
    /// The `peer_ocsp_this_update` method returns the OCSP this update time.
    ///
    /// # See also
    ///
    /// [`tls_peer_ocsp_this_update(3)`](https://man.openbsd.org/tls_peer_ocsp_this_update.3)
    pub fn peer_ocsp_this_update(&mut self) -> error::Result<SystemTime> {
        cvt_time(self, unsafe {
            libtls_sys::tls_peer_ocsp_this_update(self.0)
        })
    }

    /// OCSP validation URL.
    ///
    /// The `peer_ocsp_url` method returns the URL for OCSP validation of the peer
    /// certificate.
    ///
    /// # See also
    ///
    /// [`tls_peer_ocsp_url(3)`](https://man.openbsd.org/tls_peer_ocsp_url.3)
    pub fn peer_ocsp_url(&mut self) -> error::Result<String> {
        unsafe { cvt_string(self, libtls_sys::tls_peer_ocsp_url(self.0)) }
    }
}

impl LastError for Tls {
    /// Returns the last error of the TLS context.
    ///
    /// The `last_error` method returns an error if no error occurred with
    /// the TLS context during or since the last call to `tls_handshake`,
    /// `tls_read`, `tls_write`, `tls_close`, or `reset` involving the context,
    /// or if memory allocation failed while trying to assemble the string
    /// describing the most recent error related to the context.
    ///
    /// # See also
    ///
    /// [`tls_error(3)`](https://man.openbsd.org/tls_error.3)
    fn last_error(&self) -> error::Result<String> {
        unsafe { cvt_no_error(libtls_sys::tls_error(self.0)) }
    }

    fn to_error<T>(errstr: String) -> error::Result<T> {
        Err(error::TlsError::CtxError(errstr))
    }
}

impl AsRawFd for Tls {
    fn as_raw_fd(&self) -> RawFd {
        // Returns -1 if the fd is not set (-1 is common unix convention)
        self.1
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
            // XXX libtls doesn't close the connection in tls_free(3), but
            // XXX this wouldn't satisfy the safety rules of Rust.
            loop {
                let ret = libtls_sys::tls_close(self.0);
                if !(ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) {
                    break;
                }
            }
            libtls_sys::tls_free(self.0);
        };
    }
}

impl io::Read for Tls {
    /// Read from the TLS connection.
    ///
    /// The `read` method reads bytes of data from the connection into `buf`.
    ///
    /// # See also
    ///
    /// [`tls_read`](#method.tls_read)
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        try_tls!(self, self.tls_read(buf))
    }
}

impl io::Write for Tls {
    /// Write to the TLS connection.
    ///
    /// The `write` method writes bytes of data from `buf` to the connection.
    ///
    /// # See also
    ///
    /// [`tls_write`](#method.tls_write)
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        try_tls!(self, self.tls_write(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        try_tls!(self, self.tls_handshake()).map(|_| ())
    }
}

unsafe impl Send for Tls {}
unsafe impl Sync for Tls {}

/// Read callback for [`Tls::accept_cbs`] and [`Tls::connect_cbs`].
///
/// [`Tls::accept_cbs`]: struct.Tls.html#method.accept_cbs
/// [`Tls::connect_cbs`]: struct.Tls.html#method.connect_cbs
pub type TlsReadCb = libtls_sys::tls_read_cb;

/// Write callback for [`Tls::accept_cbs`] and [`Tls::connect_cbs`].
///
/// [`Tls::accept_cbs`]: struct.Tls.html#method.accept_cbs
/// [`Tls::connect_cbs`]: struct.Tls.html#method.connect_cbs
pub type TlsWriteCb = libtls_sys::tls_write_cb;
