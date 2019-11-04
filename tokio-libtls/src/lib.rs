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

//! Async [`Tls`] bindings for [`libtls`].
//!
//! See also [`libtls`] for more information.
//!
//! > Note, the API for this crate is neither finished nor documented yet.
//!
//! # Example
//!
//! ```rust
//! # use std::net::ToSocketAddrs;
//! # use tokio::runtime::Runtime;
//! # use tokio::io::{read_exact, write_all};
//! # use tokio_libtls::prelude::*;
//! fn async_https_connect(servername: String) -> error::Result<()> {
//!     let addr = &(servername.to_owned() + ":443")
//!         .to_socket_addrs()
//!         .unwrap()
//!         .next()
//!         .expect("to_socket_addrs");
//!
//!     let request = format!(
//!         "GET / HTTP/1.1\r\n\
//!          Host: {}\r\n\
//!          Connection: close\r\n\r\n",
//!         servername
//!     );
//!
//!     let config = TlsConfigBuilder::new().build()?;
//!
//!     let fut = TcpStream::connect(&addr)
//!         .and_then(move |tcp| AsyncTls::connect_stream(&servername, tcp, &config))
//!         .and_then(move |tls| write_all(tls, request))
//!         .and_then(|(tls, _)| {
//!		let buf = vec![0u8; 1024];
//!             read_exact(tls, buf)
//!         });
//!
//!     let mut runtime = Runtime::new()?;
//!     let (_, buf) = runtime.block_on(fut)?;
//!
//!     let ok = b"HTTP/1.1 200 OK\r\n";
//!     assert_eq!(&buf[..ok.len()], ok);
//!
//!     Ok(())
//! }
//! # fn main() {
//! #     async_https_connect("www.example.com".to_owned()).unwrap();
//! # }
//! ```
//!
//! [`Tls`]: https://reyk.github.io/rust-libtls/libtls/tls/struct.Tls.html
//! [`libtls`]: https://reyk.github.io/rust-libtls/libtls

#![doc(
    html_logo_url = "https://www.libressl.org/images/libressl.jpg",
    html_favicon_url = "https://www.libressl.org/favicon.ico"
)]
#![warn(missing_docs)]

extern crate futures;
extern crate libtls;
extern crate mio;

/// Error handling.
pub mod error;

/// A "prelude" for crates using the `tokio-libtls` crate.
pub mod prelude;

use std::io;
use std::ops::{Deref, DerefMut};

use error::AsyncTlsError;
use futures::{task, Async, Future, Poll};
use libtls::config::TlsConfig;
use libtls::error::TlsError;
use libtls::tls::Tls;
use mio::event::Evented;
use mio::unix::EventedFd;
use mio::{PollOpt, Ready, Token};
use std::os::unix::io::{AsRawFd, RawFd};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_reactor::PollEvented;
use tokio_tcp::TcpStream;

/// Wrapper for async I/O operations with `Tls`.
#[derive(Debug)]
pub struct TlsStream {
    tls: Tls,
    tcp: TcpStream,
}

impl TlsStream {
    /// Create new `TlsStream` from `Tls` object and `TcpStream`.
    pub fn new(tls: Tls, tcp: TcpStream) -> Self {
        Self { tls, tcp }
    }
}

impl Deref for TlsStream {
    type Target = Tls;

    fn deref(&self) -> &Self::Target {
        &self.tls
    }
}

impl DerefMut for TlsStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tls
    }
}

impl AsRawFd for TlsStream {
    fn as_raw_fd(&self) -> RawFd {
        self.tcp.as_raw_fd()
    }
}

impl io::Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tls.read(buf)
    }
}

impl io::Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tls.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tls.flush()
    }
}

impl AsyncRead for TlsStream {}

impl AsyncWrite for TlsStream {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        match self.tls.close() {
            Ok(res) => {
                if res == libtls::TLS_WANT_POLLIN as isize
                    || res == libtls::TLS_WANT_POLLOUT as isize
                {
                    Ok(Async::NotReady)
                } else {
                    Ok(Async::Ready(()))
                }
            }
            Err(err) => Err(io::Error::new(io::ErrorKind::Other, err)),
        }
    }
}

impl Evented for TlsStream {
    fn register(
        &self,
        poll: &mio::Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        let res = EventedFd(&self.as_raw_fd()).register(poll, token, interest, opts);
        match res {
            Err(ref err) if err.kind() == io::ErrorKind::AlreadyExists => {
                self.reregister(poll, token, interest, opts)
            }
            Err(err) => Err(err),
            Ok(_) => Ok(()),
        }
    }

    fn reregister(
        &self,
        poll: &mio::Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        EventedFd(&self.as_raw_fd()).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &mio::Poll) -> io::Result<()> {
        EventedFd(&self.as_raw_fd()).deregister(poll)
    }
}

/// Pollable wrapper for async I/O operations with `Tls`.
pub type AsyncTlsStream = PollEvented<TlsStream>;

/// Async `Tls` struct.
pub struct AsyncTls {
    inner: Option<Result<AsyncTlsStream, AsyncTlsError>>,
}

impl AsyncTls {
    /// Accept a new async `Tls` connection.
    pub fn accept_stream(tcp: TcpStream, config: &TlsConfig) -> Self {
        let tls = Tls::server()
            .and_then(|mut tls| tls.configure(config).map(|_| tls).map_err(|err| err.into()))
            .and_then(|mut tls| {
                tls.accept_raw_fd(&tcp)
                    .map(|_| tls)
                    .map_err(|err| err.into())
            })
            .map_err(|err| AsyncTlsError::Error(err.into()))
            .and_then(|tls| {
                let async_tls = TlsStream::new(tls, tcp);
                let stream = PollEvented::new(async_tls);
                Err(AsyncTlsError::Readable(stream))
            });

        Self { inner: Some(tls) }
    }

    /// Connect a new async `Tls` connection.
    pub fn connect_stream(servername: &str, tcp: TcpStream, config: &TlsConfig) -> Self {
        let tls = Tls::client()
            .and_then(|mut tls| tls.configure(config).map(|_| tls).map_err(|err| err.into()))
            .and_then(|mut tls| {
                tls.connect_raw_fd(&tcp, servername)
                    .map(|_| tls)
                    .map_err(|err| err.into())
            })
            .map_err(|err| {
                eprintln!("connect error: {:?}", err);
                AsyncTlsError::Error(err.into())
            })
            .and_then(|tls| {
                let async_tls = TlsStream::new(tls, tcp);
                let stream = PollEvented::new(async_tls);
                Err(AsyncTlsError::Readable(stream))
            });

        Self { inner: Some(tls) }
    }
}

impl Future for AsyncTls {
    type Item = AsyncTlsStream;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<AsyncTlsStream, Self::Error> {
        let inner = self
            .inner
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "cannot take inner"))?;
        match inner {
            Ok(tls) => {
                task::current().notify();
                Ok(Async::Ready(tls))
            }
            Err(AsyncTlsError::Readable(stream)) => {
                stream.poll_read_ready(Ready::readable())?;
                self.inner = Some(Err(AsyncTlsError::Handshake(stream)));
                task::current().notify();
                Ok(Async::NotReady)
            }
            Err(AsyncTlsError::Writeable(stream)) => {
                stream.poll_write_ready()?;
                self.inner = Some(Err(AsyncTlsError::Handshake(stream)));
                task::current().notify();
                Ok(Async::NotReady)
            }
            Err(AsyncTlsError::Handshake(mut stream)) => {
                let tls = &mut *stream.get_mut();
                let res = match tls.tls_handshake() {
                    Ok(res) => {
                        if res == libtls::TLS_WANT_POLLIN as isize {
                            Err(AsyncTlsError::Readable(stream))
                        } else if res == libtls::TLS_WANT_POLLOUT as isize {
                            Err(AsyncTlsError::Writeable(stream))
                        } else {
                            Ok(stream)
                        }
                    }
                    Err(err) => Err(err.into()),
                };
                self.inner = Some(res);
                task::current().notify();
                Ok(Async::NotReady)
            }
            Err(AsyncTlsError::Error(TlsError::IoError(err))) => Err(err),
            Err(AsyncTlsError::Error(err)) => {
                Err(io::Error::new(io::ErrorKind::Other, err.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::prelude::*;
    use std::net::ToSocketAddrs;
    use tokio::runtime::Runtime;
    use tokio_io::io::{read_exact, write_all};

    fn async_https_connect(servername: String) -> error::Result<()> {
        let addr = &(servername.to_owned() + ":443")
            .to_socket_addrs()
            .unwrap()
            .next()
            .expect("to_socket_addrs");

        let request = format!(
            "GET / HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: close\r\n\r\n",
            servername
        );

        let config = TlsConfigBuilder::new().build()?;

        let fut = TcpStream::connect(&addr)
            .and_then(move |tcp| AsyncTls::connect_stream(&servername, tcp, &config))
            .and_then(move |tls| write_all(tls, request))
            .and_then(|(tls, _)| {
                let buf = vec![0u8; 1024];
                read_exact(tls, buf)
            });

        let mut runtime = Runtime::new()?;
        let (_, buf) = runtime.block_on(fut)?;

        let ok = b"HTTP/1.1 200 OK\r\n";
        assert_eq!(&buf[..ok.len()], ok);

        Ok(())
    }

    #[test]
    fn test_async_https_connect() {
        async_https_connect("www.example.com".to_owned()).unwrap();
    }
}
