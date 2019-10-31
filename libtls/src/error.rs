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

use std::ffi::{self, CStr, CString};
use std::fmt;
use std::io;
use std::os::raw::{c_char, c_int};

use super::config::TlsConfig;

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
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TlsError::CtxError(s) => write!(f, "{}", s),
            TlsError::ConfigError(s) => write!(f, "{}", s),
            TlsError::IoError(err) => err.fmt(f),
            TlsError::NulError(err) => err.fmt(f),
        }
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

/// A result type that is returning a [TlsError](enum.TlsError.html).
pub type Result<T> = std::result::Result<T, TlsError>;

#[doc(hidden)]
pub fn cvt<T>(config: &mut TlsConfig, ok: T, retval: c_int) -> Result<T> {
    match retval {
        -1 => {
            // Instead of storing a reference to the error context in TlsError
            // (by storing the *mut tls_config to call tls_config_error() later),
            // we store the actual error as a String.  This needs a bit more
            // memory but it is safe to transfer the error between threads and
            // to use it later, even after the config is dropped.
            let errstr = config.last_error();
            Err(TlsError::ConfigError(errstr))
        }
        _ => Ok(ok),
    }
}

#[doc(hidden)]
pub fn cvt_io<T, E>(ok: T, retval: c_int) -> std::result::Result<T, E>
where
    E: std::convert::From<io::Error>,
{
    match retval {
        -1 => Err(io::Error::last_os_error().into()),
        _ => Ok(ok),
    }
}

#[doc(hidden)]
pub fn cvt_option<T>(option: Option<T>, error: io::Error) -> Result<T> {
    match option {
        None => Err(TlsError::IoError(error)),
        Some(v) => Ok(v),
    }
}

#[doc(hidden)]
pub unsafe fn cvt_string(error: *const c_char, default: &str) -> String {
    let c_default = CString::new(default).expect("default error contains nul");
    let c_str = if error.is_null() {
        &c_default
    } else {
        CStr::from_ptr(error)
    };
    c_str.to_string_lossy().into_owned()
}
