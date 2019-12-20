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

use crate::{
    config::Config,
    error::{Error, LastError, Result},
};
use libtls_sys::time_t;
use std::{
    convert::TryInto,
    ffi::{CStr, CString},
    io,
    os::raw::{c_char, c_int},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// XXX Convert functions into macros.

pub fn call_file1<P: AsRef<Path>>(
    config: &mut Config,
    file1: (P, &str),
    f: unsafe extern "C" fn(*mut libtls_sys::tls_config, *const c_char) -> c_int,
) -> Result<()> {
    let s_file1 = cvt_option(
        file1.0.as_ref().to_str(),
        io::Error::new(io::ErrorKind::InvalidData, file1.1),
    )?;
    unsafe {
        let c_file1 = CString::new(s_file1)?;
        cvt(config, f(config.0, c_file1.as_ptr()))
    }
}

pub fn call_file2<P: AsRef<Path>>(
    config: &mut Config,
    file1: (P, &str),
    file2: (P, &str),
    f: unsafe extern "C" fn(*mut libtls_sys::tls_config, *const c_char, *const c_char) -> c_int,
) -> Result<()> {
    let s_file1 = cvt_option(
        file1.0.as_ref().to_str(),
        io::Error::new(io::ErrorKind::InvalidData, file1.1),
    )?;
    let s_file2 = cvt_option(
        file2.0.as_ref().to_str(),
        io::Error::new(io::ErrorKind::InvalidData, file2.1),
    )?;
    unsafe {
        let c_file1 = CString::new(s_file1)?;
        let c_file2 = CString::new(s_file2)?;
        cvt(config, f(config.0, c_file1.as_ptr(), c_file2.as_ptr()))
    }
}

pub fn call_file3<P: AsRef<Path>>(
    config: &mut Config,
    file1: (P, &str),
    file2: (P, &str),
    file3: (P, &str),
    f: unsafe extern "C" fn(
        *mut libtls_sys::tls_config,
        *const c_char,
        *const c_char,
        *const c_char,
    ) -> c_int,
) -> Result<()> {
    let s_file1 = cvt_option(
        file1.0.as_ref().to_str(),
        io::Error::new(io::ErrorKind::InvalidData, file1.1),
    )?;
    let s_file2 = cvt_option(
        file2.0.as_ref().to_str(),
        io::Error::new(io::ErrorKind::InvalidData, file2.1),
    )?;
    let s_file3 = cvt_option(
        file3.0.as_ref().to_str(),
        io::Error::new(io::ErrorKind::InvalidData, file3.1),
    )?;
    unsafe {
        let c_file1 = CString::new(s_file1)?;
        let c_file2 = CString::new(s_file2)?;
        let c_file3 = CString::new(s_file3)?;
        cvt(
            config,
            f(
                config.0,
                c_file1.as_ptr(),
                c_file2.as_ptr(),
                c_file3.as_ptr(),
            ),
        )
    }
}

pub fn call_string1(
    config: &mut Config,
    string1: &str,
    f: unsafe extern "C" fn(*mut libtls_sys::tls_config, *const c_char) -> c_int,
) -> Result<()> {
    unsafe {
        let c_string1 = CString::new(string1)?;
        cvt(config, f(config.0, c_string1.as_ptr()))
    }
}

pub fn call_arg1<T>(
    config: &mut Config,
    arg1: T,
    f: unsafe extern "C" fn(*mut libtls_sys::tls_config, T) -> c_int,
) -> Result<()> {
    cvt(config, unsafe { f(config.0, arg1) })
}

pub fn cvt<E>(object: &mut E, retval: c_int) -> Result<()>
where
    E: LastError,
{
    match retval {
        -1 => {
            // Instead of storing a reference to the error context in Error
            // (by storing the *mut tls* to call tls_*error() later),
            // we store the actual error as a String.  This needs a bit more
            // memory but it is safe to transfer the error between threads and
            // to use it later, even after the config or TLS object is dropped.
            let errstr = object
                .last_error()
                .unwrap_or_else(|_| "no error".to_string());
            E::to_error(errstr)
        }
        _ => Ok(()),
    }
}

pub fn cvt_err<E>(object: &mut E, retval: isize) -> Result<isize>
where
    E: LastError,
{
    if retval == -1 {
        let errstr = object
            .last_error()
            .unwrap_or_else(|_| "no error".to_string());
        E::to_error(errstr)
    } else {
        Ok(retval)
    }
}

pub fn cvt_io<T, E>(ok: T, retval: c_int) -> std::result::Result<T, E>
where
    E: std::convert::From<io::Error>,
{
    match retval {
        -1 => Err(io::Error::last_os_error().into()),
        _ => Ok(ok),
    }
}

pub fn cvt_time<E>(object: &mut E, itime: time_t) -> Result<SystemTime>
where
    E: LastError,
{
    if itime < 0 {
        let errstr = object
            .last_error()
            .unwrap_or_else(|_| "no error".to_string());
        E::to_error(errstr)
    } else {
        let utime: u64 = itime.try_into()?;
        let time: SystemTime = UNIX_EPOCH + Duration::from_secs(utime);
        Ok(time)
    }
}

/// Convert C string return to a Rust result and string.
///
/// # Safety
///
/// This internal function must be called from `unsafe` context because it calls
/// C-to-Rust string conversions.
pub unsafe fn cvt_string<E>(object: &mut E, retval: *const c_char) -> Result<String>
where
    E: LastError,
{
    if retval.is_null() {
        let errstr = object
            .last_error()
            .unwrap_or_else(|_| "no error".to_string());
        E::to_error(errstr)
    } else {
        let c_str = CStr::from_ptr(retval);
        let string = c_str.to_owned().to_string_lossy().to_string();
        Ok(string)
    }
}

/// Like [`cvt_string`], but return an error code if the C string is NULL.
///
/// # Safety
///
/// This internal function must be called from `unsafe` context because it calls
/// C-to-Rust string conversions.
///
/// [`cvt_string`]: fn.cvt_string.html
pub unsafe fn cvt_no_error(error: *const c_char) -> Result<String> {
    if error.is_null() {
        Err(Error::NoError)
    } else {
        Ok(CStr::from_ptr(error).to_string_lossy().into_owned())
    }
}

pub fn cvt_option<T>(option: Option<T>, error: io::Error) -> Result<T> {
    match option {
        None => Err(Error::IoError(error)),
        Some(v) => Ok(v),
    }
}
