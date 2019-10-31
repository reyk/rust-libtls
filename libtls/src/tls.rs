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

use super::error;

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

    /// XXX tls_reset
    pub fn reset(&mut self) {
        unsafe { libtls::tls_reset(self.0) };
    }

    /// XXX tls_error
    pub fn last_error(&self) -> String {
        unsafe {
            let c_error = libtls::tls_error(self.0);
            error::cvt_string(c_error, "no TLS error")
        }
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
    /// XXX tls_config_free
    fn drop(&mut self) {
        unsafe { libtls::tls_free(self.0) };
    }
}
