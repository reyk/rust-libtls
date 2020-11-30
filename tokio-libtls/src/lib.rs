// Copyright (c) 2019, 2020 Reyk Floeter <contact@reykfloeter.com>
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
//! use std::io;
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//! use tokio_libtls::prelude::{connect, Builder};
//!
//! async fn async_https_connect(servername: String) -> io::Result<()> {
//!     let request = format!(
//!         "GET / HTTP/1.1\r\n\
//!          Host: {}\r\n\
//!          Connection: close\r\n\r\n",
//!         servername
//!     );
//!
//!     let config = Builder::new().build()?;
//!     let mut tls = connect(&(servername + ":443"), &config, None).await?;
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

/// A "prelude" for crates using the `tokio-libtls` crate.
pub mod prelude;

use futures::ready;
use libtls::{config::Config, error::Error as TlsError, tls::Tls};
use prelude::*;
use std::{
    io,
    net::ToSocketAddrs,
    ops::{Deref, DerefMut},
    os::unix::io::{AsRawFd, RawFd},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    time::timeout,
};

/// Wrapper for async I/O operations with `Tls`.
#[derive(Debug)]
pub struct TlsStream {
    /// The underlying `Tls` instance for this `TlsStream`.
    pub tls: Tls,
    /// The underlying `TcpStream` for this `TlsStream`.
    ///
    /// This can be used to poll the readable and writable status of the socket, if necessary.
    pub tcp: TcpStream,
}

impl TlsStream {
    /// Create new `TlsStream` from `Tls` object and `TcpStream`.
    pub fn new(tls: Tls, tcp: TcpStream) -> Self {
        Self { tls, tcp }
    }

    /// Attempts an IO action, handling `TLS_WANT_POLLIN` and `TLS_WANT_POLLOUT`.
    ///
    /// This function calls `f` repeatedly, rescheduling this task whenever it returns
    /// `TLS_WANT_POLLIN` or `TLS_WANT_POLLOUT`.
    fn poll_io(
        &mut self,
        cx: &mut Context<'_>,
        mut f: impl FnMut(&mut Tls) -> Result<isize, TlsError>,
    ) -> Poll<io::Result<isize>> {
        loop {
            match f(&mut self.tls) {
                Err(err) => return Poll::Ready(Err(err.into())),
                Ok(value) => {
                    if value == libtls::TLS_WANT_POLLIN as isize {
                        ready!(self.tcp.poll_read_ready(cx)?);
                    } else if value == libtls::TLS_WANT_POLLOUT as isize {
                        ready!(self.tcp.poll_write_ready(cx)?);
                    } else {
                        return Poll::Ready(Ok(value));
                    }
                }
            }
        }
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
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // libtls should correctly fill the uninintialized buffer, so this unsafe is okay
        unsafe {
            let b = &mut *(buf.unfilled_mut() as *mut [std::mem::MaybeUninit<u8>] as *mut [u8]);
            let n = ready!(self.poll_io(cx, |tls| tls.tls_read(b))?) as usize;
            buf.assume_init(n);
            buf.advance(n);
            Poll::Ready(Ok(()))
        }
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let n = ready!(self.poll_io(cx, |tls| tls.tls_write(buf))?) as usize;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        ready!(self.poll_io(cx, |tls| tls.tls_close())?);
        Poll::Ready(Ok(()))
    }
}

unsafe impl Send for TlsStream {}
unsafe impl Sync for TlsStream {}

/// Async `Tls` struct.
pub struct AsyncTls {
    stream: Option<TlsStream>,
}

impl AsyncTls {
    /// Accept a new async `Tls` connection.
    #[deprecated(since = "1.1.1", note = "Please use module function `accept_stream`")]
    pub async fn accept_stream(
        tcp: TcpStream,
        config: &Config,
        options: Option<Options>,
    ) -> io::Result<TlsStream> {
        accept_stream(tcp, config, options).await
    }

    /// Upgrade a TCP stream to a new async `Tls` connection.
    #[deprecated(since = "1.1.1", note = "Please use module function `connect_stream`")]
    pub async fn connect_stream(
        tcp: TcpStream,
        config: &Config,
        options: Option<Options>,
    ) -> io::Result<TlsStream> {
        connect_stream(tcp, config, options).await
    }

    /// Connect a new async `Tls` connection.
    #[deprecated(since = "1.1.1", note = "Please use module function `connect`")]
    pub async fn connect(
        host: &str,
        config: &Config,
        options: Option<Options>,
    ) -> io::Result<TlsStream> {
        connect(host, config, options).await
    }
}

impl Future for AsyncTls {
    type Output = Result<TlsStream, io::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let stream = self
            .stream
            .as_mut()
            .expect("AsyncTls::poll called again after returning Poll::Ready");
        ready!(stream.poll_io(cx, |tls| tls.tls_handshake())?);
        Poll::Ready(Ok(self.stream.take().unwrap()))
    }
}

unsafe impl Send for AsyncTls {}
unsafe impl Sync for AsyncTls {}

/// Accept a new async `Tls` connection.
pub async fn accept(
    listener: &mut TcpListener,
    config: &Config,
    options: Option<Options>,
) -> io::Result<TlsStream> {
    let options = options.unwrap_or_else(Options::new);

    let (tcp, _) = listener.accept().await?;
    let mut server = Tls::server()?;
    server.configure(config)?;
    let client = server.accept_raw_fd(&tcp)?;

    let stream = TlsStream::new(client, tcp);
    let fut = AsyncTls {
        stream: Some(stream),
    };

    // Accept with an optional timeout for the TLS handshake.
    let tls = match options.timeout {
        Some(tm) => match timeout(tm, fut).await {
            Ok(res) => res,
            Err(err) => Err(err.into()),
        },
        None => fut.await,
    }?;

    Ok(tls)
}

/// Accept a new async `Tls` connection on an established client connection.
pub async fn accept_stream(
    tcp: TcpStream,
    config: &Config,
    options: Option<Options>,
) -> io::Result<TlsStream> {
    let options = options.unwrap_or_else(Options::new);

    let mut server = Tls::server()?;
    server.configure(config)?;
    let client = server.accept_raw_fd(&tcp)?;

    let stream = TlsStream::new(client, tcp);
    let fut = AsyncTls {
        stream: Some(stream),
    };

    // Accept with an optional timeout for the TLS handshake.
    let tls = match options.timeout {
        Some(tm) => match timeout(tm, fut).await {
            Ok(res) => res,
            Err(err) => Err(err.into()),
        },
        None => fut.await,
    }?;

    Ok(tls)
}

/// Upgrade a TCP stream to a new async `Tls` connection.
pub async fn connect_stream(
    tcp: TcpStream,
    config: &Config,
    options: Option<Options>,
) -> io::Result<TlsStream> {
    let options = options.unwrap_or_else(Options::new);
    let servername = match options.servername {
        Some(name) => name,
        None => tcp.peer_addr()?.to_string(),
    };

    let mut tls = Tls::client()?;

    tls.configure(config)?;
    tls.connect_raw_fd(&tcp, &servername)?;

    let stream = TlsStream::new(tls, tcp);
    let fut = AsyncTls {
        stream: Some(stream),
    };

    // Connect with an optional timeout for the TLS handshake.
    let tls = match options.timeout {
        Some(tm) => match timeout(tm, fut).await {
            Ok(res) => res,
            Err(err) => Err(err.into()),
        },
        None => fut.await,
    }?;

    Ok(tls)
}

/// Connect a new async `Tls` connection.
pub async fn connect(
    host: &str,
    config: &Config,
    options: Option<Options>,
) -> io::Result<TlsStream> {
    let mut options = options.unwrap_or_else(Options::new);

    // Remove _last_ colon (to satisfy the IPv6 form, e.g. [::1]::443).
    if options.servername.is_none() {
        match host.rfind(':') {
            None => return Err(io::ErrorKind::InvalidInput.into()),
            Some(index) => options.servername(&host[0..index]),
        };
    };

    let mut last_error = io::ErrorKind::ConnectionRefused.into();

    for addr in host.to_socket_addrs()? {
        // Connect with an optional timeout.
        let res = match options.timeout {
            Some(tm) => match timeout(tm, TcpStream::connect(&addr)).await {
                Ok(res) => res,
                Err(err) => Err(err.into()),
            },
            None => TcpStream::connect(&addr).await,
        };

        // Return the first TCP successful connection, store the last error.
        match res {
            Ok(tcp) => {
                return connect_stream(tcp, config, Some(options)).await;
            }
            Err(err) => last_error = err,
        }
    }

    Err(last_error)
}

/// Configuration options for `AsyncTls`.
///
/// # See also
///
/// [`AsyncTls`]
///
/// [`AsyncTls`]: ./struct.AsyncTls.html
#[derive(Clone, Default, Debug, PartialEq)]
pub struct Options {
    timeout: Option<Duration>,
    servername: Option<String>,
}

/// Configuration options for `AsyncTls`.
#[deprecated(
    since = "1.1.1",
    note = "Please use `Options` instead of `AsyncTlsOptions`"
)]
pub type AsyncTlsOptions = Options;

impl Options {
    /// Return new empty `Options` struct.
    pub fn new() -> Self {
        Default::default()
    }

    /// Set the optional TCP connection and TLS handshake timeout.
    pub fn timeout(&'_ mut self, timeout: Duration) -> &'_ mut Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the optional TLS servername.
    ///
    /// If not specified, the address is derived from the host or address.
    pub fn servername(&'_ mut self, servername: &str) -> &'_ mut Self {
        self.servername = Some(servername.to_owned());
        self
    }

    /// Return as `Some(Options)` or `None` if the options are empty.
    pub fn build(&'_ mut self) -> Option<Self> {
        if self == &mut Self::new() {
            None
        } else {
            Some(self.clone())
        }
    }
}

#[cfg(test)]
mod test {
    use crate::prelude::*;
    use std::{io, time::Duration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn async_https_connect(servername: String) -> io::Result<()> {
        let request = format!(
            "GET / HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: close\r\n\r\n",
            servername
        );

        let config = Builder::new().build()?;
        let options = Options::new()
            .servername(&servername)
            .timeout(Duration::from_secs(60))
            .build();
        let mut tls = connect(&(servername + ":443"), &config, options).await?;
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
