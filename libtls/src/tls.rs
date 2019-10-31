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

use std::io;

use super::*;

/// XXX tls
pub struct Tls(*mut libtls::tls);

impl Tls {
    fn new(f: unsafe extern "C" fn() -> *mut libtls::tls) -> io::Result<Self> {
        let tls = unsafe { f() };
        if tls.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Tls(tls))
        }
    }

    /// XXX tls_client
    pub fn client() -> io::Result<Self> {
        Self::new(libtls::tls_client)
    }

    /// XXX tls_server
    pub fn server() -> io::Result<Self> {
        Self::new(libtls::tls_server)
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

    /// Returns the last error of the TLS context.
    ///
    /// The `last_error` method returns an error if no error occurred with
    /// the TLS context during or since the last call to [`handshake`],
    /// [`read`], [`write`], [`close`], or [`reset`] involving the context,
    /// or if memory allocation failed while trying to assemble the string
    /// describing the most recent error related to the context.
    ///
    /// # See also
    ///
    /// [`tls_error(3)`](https://man.openbsd.org/tls_error.3)
    ///
    /// [`handshake`]: #method.handshake
    /// [`read`]: #method.read
    /// [`write`]: #method.write
    /// [`close`]: #method.close
    /// [`reset`]: #method.reset
    pub fn last_error(&self) -> error::Result<String> {
        unsafe { cvt_no_error(libtls::tls_error(self.0)) }
    }
}

impl From<*mut libtls::tls> for Tls {
    fn from(tls: *mut libtls::tls) -> Self {
        if tls.is_null() {
            panic!(io::Error::last_os_error())
        }
        Tls(tls)
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
            libtls::tls_free(self.0);
        };
    }
}
