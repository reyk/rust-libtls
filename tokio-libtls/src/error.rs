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
use libtls::error::TlsError;
use std::{error, fmt, io};

/// An error returned by [`AsyncTls`].
///
/// This error includes the detailed error message of a failed async
/// `libtls` operation.
///
/// [`AsyncTls`]: ../struct.AsyncTls.html
#[derive(Debug)]
pub enum AsyncTlsError {
    /// The connection is readable.
    Readable(AsyncTlsStream),
    /// The connection is writeable.
    Writeable(AsyncTlsStream),
    /// The connection is doing a handshake.
    Handshake(AsyncTlsStream),
    /// A generic error.
    Error(TlsError),
}

impl fmt::Display for AsyncTlsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AsyncTlsError::Readable(_) => write!(f, "Readable I/O in progress"),
            AsyncTlsError::Writeable(_) => write!(f, "Writable I/O in progress"),
            AsyncTlsError::Handshake(_) => write!(f, "Handshake I/O in progress"),
            AsyncTlsError::Error(err) => err.fmt(f),
        }
    }
}

impl error::Error for AsyncTlsError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<TlsError> for AsyncTlsError {
    fn from(err: TlsError) -> Self {
        AsyncTlsError::Error(err)
    }
}

impl From<io::Error> for AsyncTlsError {
    fn from(err: io::Error) -> Self {
        err.into()
    }
}

impl From<AsyncTlsError> for io::Error {
    fn from(err: AsyncTlsError) -> Self {
        io::Error::new(io::ErrorKind::Other, err)
    }
}
