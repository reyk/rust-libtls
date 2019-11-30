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

use std::{error, ffi, fmt, io, num};

/// An error returned by [`Tls`] and [`TlsConfig`] methods.
///
/// This error includes the detailed error message of a failed `libtls`
/// operation.
///
/// [`Tls`]: ../tls/struct.Tls.html
/// [`TlsConfig`]: ../config/struct.TlsConfig.html
#[derive(Debug)]
pub enum TlsError {
    /// [`Tls`](../tls/struct.Tls.html) error.
    ///
    /// # See also
    ///
    /// [`Tls::last_error`](../tls/struct.Tls.html#method.last_error),
    /// [`tls_error(3)`](https://man.openbsd.org/tls_error.3)
    CtxError(String),
    /// [`TlsConfig`](../config/struct.TlsConfig.html) error.
    ///
    /// # See also
    ///
    /// [`TlsConfig::last_error`](../config/struct.TlsConfig.html#method.last_error),
    /// [`tls_config_error(3)`](https://man.openbsd.org/tls_config_error.3)
    ConfigError(String),
    /// Generic operating system or I/O error.
    IoError(io::Error),
    /// An interior nul byte was found.
    NulError(ffi::NulError),
    /// No error was reported.
    NoError,
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TlsError::CtxError(s) => write!(f, "tls context: {}", s),
            TlsError::ConfigError(s) => write!(f, "tls config: {}", s),
            TlsError::IoError(err) => err.fmt(f),
            TlsError::NulError(err) => err.fmt(f),
            TlsError::NoError => write!(f, "no error"),
        }
    }
}

impl error::Error for TlsError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<io::Error> for TlsError {
    fn from(err: io::Error) -> Self {
        TlsError::IoError(err)
    }
}

impl From<ffi::NulError> for TlsError {
    fn from(err: ffi::NulError) -> Self {
        TlsError::NulError(err)
    }
}

impl From<num::TryFromIntError> for TlsError {
    fn from(err: num::TryFromIntError) -> Self {
        TlsError::IoError(io::Error::new(io::ErrorKind::Other, err))
    }
}

impl From<TlsError> for io::Error {
    fn from(err: TlsError) -> Self {
        io::Error::new(io::ErrorKind::Other, err)
    }
}

/// A result type that is returning a [TlsError](enum.TlsError.html).
pub type Result<T> = std::result::Result<T, TlsError>;

/// Returns the last API error.
///
/// The [`Tls`] and [`TlsConfig`] structs both provide a way to return
/// the last error as a String from the underlying API.
///
/// [`Tls`]: ../tls/struct.Tls.html
/// [`TlsConfig`]: ../tls/struct.TlsConfig.html
pub trait LastError {
    /// Return the last error of the underlying API.
    ///
    /// The `last_error` method returns an error if no error occurred
    /// at all, or if memory allocation failed while trying to assemble the
    /// string describing the most recent error related to config.
    fn last_error(&self) -> Result<String>;

    /// Returns the error string as an error object.
    fn to_error<T>(errstr: String) -> Result<T> {
        Err(TlsError::ConfigError(errstr))
    }
}
