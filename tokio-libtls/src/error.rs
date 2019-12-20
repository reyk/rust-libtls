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

use crate::AsyncTlsStream;
use libtls::error::Error as TlsError;
use std::{error, fmt, io};

/// An error returned by [`AsyncTls`].
///
/// This error includes the detailed error message of a failed async
/// `libtls` operation.
///
/// [`AsyncTls`]: ../struct.AsyncTls.html
#[derive(Debug)]
pub enum Error {
    /// The connection is readable.
    Readable(AsyncTlsStream),
    /// The connection is writeable.
    Writeable(AsyncTlsStream),
    /// The connection is doing a handshake.
    Handshake(AsyncTlsStream),
    /// A generic error.
    Error(TlsError),
}

/// An error returned by [`AsyncTls`].
#[deprecated(
    since = "1.1.1",
    note = "Please use `Error` instead of `AsyncTlsError`"
)]
pub type AsyncTlsError = Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Readable(_) => write!(f, "Readable I/O in progress"),
            Error::Writeable(_) => write!(f, "Writable I/O in progress"),
            Error::Handshake(_) => write!(f, "Handshake I/O in progress"),
            Error::Error(err) => err.fmt(f),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<TlsError> for Error {
    fn from(err: TlsError) -> Self {
        Error::Error(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        err.into()
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> Self {
        io::Error::new(io::ErrorKind::Other, err)
    }
}
