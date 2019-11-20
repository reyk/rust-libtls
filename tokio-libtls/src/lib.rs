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
//! # use std::io;
//! # use tokio::io::{AsyncReadExt, AsyncWriteExt};
//! # use tokio_libtls::prelude::*;
//! #
//! async fn async_https_connect(servername: String) -> io::Result<()> {
//!     let request = format!(
//!         "GET / HTTP/1.1\r\n\
//!          Host: {}\r\n\
//!          Connection: close\r\n\r\n",
//!         servername
//!     );
//!
//!     let config = TlsConfigBuilder::new().build()?;
//!     let mut tls = AsyncTls::connect(&(servername + ":443"), &config).await?;
//!     tls.write_all(request.as_bytes()).await?;
//!
//!     let mut buf = vec![0u8; 1024];
//!     tls.read_exact(&mut buf).await?;
//!
//!     let ok = b"HTTP/1.1 200 OK\r\n";
//!     assert_eq!(&buf[..ok.len()], ok);
//!
//!     Ok(())
//! }
//! # #[tokio::main]
//! # async fn main() {
//! #    async_https_connect("www.example.com".to_owned()).await.unwrap();
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

extern crate libtls;
extern crate mio;

/// Error handling.
pub mod error;

/// A "prelude" for crates using the `tokio-libtls` crate.
pub mod prelude;

use std::io::{self, Read, Write};
use std::net::ToSocketAddrs;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};

use error::AsyncTlsError;
use libtls::config::TlsConfig;
use libtls::error::TlsError;
use libtls::tls::Tls;
use mio::event::Evented;
use mio::unix::EventedFd;
use mio::{PollOpt, Ready, Token};
use prelude::*;
use std::os::unix::io::{AsRawFd, RawFd};
use tokio::net::TcpStream;
use tokio_net::util::PollEvented;

macro_rules! try_async_tls {
    ($call: expr) => {
        match $call {
            Ok(size) => Poll::Ready(Ok(size)),
            Err(err) => {
                let err: io::Error = err.into();
                if err.kind() == io::ErrorKind::WouldBlock {
                    Poll::Pending
                } else {
                    Poll::Ready(Err(err))
                }
            }
        }
    };
}

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

impl AsyncRead for TlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        try_async_tls!(self.tls.read(buf))
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        try_async_tls!(self.tls.write(buf))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), io::Error>> {
        try_async_tls!(self.tls.close()).map(|_| Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), io::Error>> {
        try_async_tls!(self.tls.close()).map(|_| Ok(()))
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
        match EventedFd(&self.as_raw_fd()).register(poll, token, interest, opts) {
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
    pub async fn accept_stream(tcp: TcpStream, config: &TlsConfig) -> io::Result<AsyncTlsStream> {
        let mut tls = Tls::server()?;
        tls.configure(config)?;
        tls.accept_raw_fd(&tcp)?;

        let async_tls = TlsStream::new(tls, tcp);
        let stream = PollEvented::new(async_tls);
        let fut = Self {
            inner: Some(Err(AsyncTlsError::Readable(stream))),
        };

        let tls = fut.await?;

        Ok(tls)
    }

    /// Upgrade a TCP stream to a new async `Tls` connection.
    pub async fn connect_stream(
        servername: &str,
        tcp: TcpStream,
        config: &TlsConfig,
    ) -> io::Result<AsyncTlsStream> {
        let mut tls = Tls::client()?;
        tls.configure(config)?;
        tls.connect_raw_fd(&tcp, servername)?;

        let async_tls = TlsStream::new(tls, tcp);
        let stream = PollEvented::new(async_tls);
        let fut = Self {
            inner: Some(Err(AsyncTlsError::Readable(stream))),
        };

        let tls = fut.await?;

        Ok(tls)
    }

    /// Connect a new async `Tls` connection.
    pub async fn connect(host: &str, config: &TlsConfig) -> io::Result<AsyncTlsStream> {
        // Remove _last_ colon (to satisfy the IPv6 form, e.g. [::1]::443).
        let servername = match host.rfind(':') {
            None => return Err(io::ErrorKind::InvalidInput.into()),
            Some(index) => &host[0..index],
        };

        let mut last_error = io::ErrorKind::ConnectionRefused.into();

        for addr in host.to_socket_addrs()? {
            // Return the first TCP successful connection, store the last error.
            match TcpStream::connect(&addr).await {
                Ok(tcp) => {
                    return Self::connect_stream(servername, tcp, config).await;
                }
                Err(err) => last_error = err,
            }
        }

        Err(last_error)
    }
}

impl Future for AsyncTls {
    type Output = Result<AsyncTlsStream, io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let inner = self
            .inner
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "cannot take inner"))?;
        match inner {
            Ok(tls) => {
                cx.waker().wake_by_ref();
                Poll::Ready(Ok(tls))
            }
            Err(AsyncTlsError::Readable(stream)) => {
                self.inner = match stream.poll_read_ready(cx, Ready::readable()) {
                    Poll::Ready(_) => Some(Err(AsyncTlsError::Handshake(stream))),
                    _ => Some(Err(AsyncTlsError::Handshake(stream))),
                };
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(AsyncTlsError::Writeable(stream)) => {
                self.inner = match stream.poll_write_ready(cx) {
                    Poll::Ready(_) => Some(Err(AsyncTlsError::Handshake(stream))),
                    _ => Some(Err(AsyncTlsError::Writeable(stream))),
                };
                cx.waker().wake_by_ref();
                Poll::Pending
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
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(AsyncTlsError::Error(TlsError::IoError(err))) => Poll::Ready(Err(err)),
            Err(AsyncTlsError::Error(err)) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, err.to_string())))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::prelude::*;
    use std::io;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn async_https_connect(servername: String) -> io::Result<()> {
        let request = format!(
            "GET / HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: close\r\n\r\n",
            servername
        );

        let config = TlsConfigBuilder::new().build()?;
        let mut tls = AsyncTls::connect(&(servername + ":443"), &config).await?;
        tls.write_all(request.as_bytes()).await?;

        let mut buf = vec![0u8; 1024];
        tls.read_exact(&mut buf).await?;

        let ok = b"HTTP/1.1 200 OK\r\n";
        assert_eq!(&buf[..ok.len()], ok);

        Ok(())
    }

    #[tokio::test]
    async fn test_async_https_connect() {
        async_https_connect("www.example.com".to_owned())
            .await
            .unwrap();
    }
}
