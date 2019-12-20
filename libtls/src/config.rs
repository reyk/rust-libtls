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

//! [`Tls`] clients and servers are configured with the [`Config`]
//! configuration context and its helper funtions.
//!
//! # Example
//!
//! ```
//! use libtls::{config::{self, Config}, error};
//!
//! fn tls_server_config() -> error::Result<Config> {
//!     let mut tls_config = Config::new()?;
//!
//!     let valid_cert = include_bytes!("../tests/eccert.crt");
//!     let valid_key = include_bytes!("../tests/eccert.key");
//!
//!     // Sets the key pair and wipes the private key file from memory afterwards
//!     let res = tls_config.set_keypair_mem(valid_cert, valid_key);
//!     config::unload_file(valid_key.to_vec());
//!     res?;
//!
//!     // The following examples are all set by default and it is not
//!     // not required to set them.
//!     tls_config.set_ciphers("secure")?;
//!     tls_config.set_protocols(libtls::TLS_PROTOCOLS_DEFAULT)?;
//!     tls_config.prefer_ciphers_server();
//!     tls_config.verify();
//!
//!     Ok(tls_config)
//! }
//! # let tls_config = tls_server_config().unwrap();
//! ```
//!
//! [`Tls`]: ../tls/struct.Tls.html
//! [`Config`]: struct.Config.html

use crate::{error, tls::Tls, util::*};
use std::{
    collections::HashMap,
    ffi::{CStr, CString},
    io,
    marker::{Send, Sync},
    os::unix::io::RawFd,
    path::{Path, PathBuf},
};

/// The TLS configuration context for [`Tls`] connections.
///
/// Before a [`Tls`] connection is created, a configuration must be created.
/// Several methods exist to change the options of the configuration; see
/// [`set_protocols`], [`ocsp_require_stapling`], [`verify`].
///
/// [`Tls`]: ../tls/struct.Tls.html
/// [`ocsp_require_stapling`]: #method.ocsp_require_stapling
/// [`set_protocols`]: #method.set_protocols
/// [`tls_config_load_file`]: ../fn.tls_config_load_file.html
/// [`verify`]: #method.verify
#[derive(Debug)]
pub struct Config(pub(crate) *mut libtls_sys::tls_config);

/// The TLS configuration context for [`Tls`] connections.
#[deprecated(since = "1.1.1", note = "Please use `Config` instead of `TlsConfig`")]
pub type TlsConfig = Config;

impl Config {
    /// Create a new configuration.
    ///
    /// The `new` function allocates, initializes, and returns a new default
    /// configuration object that can be used for future [`Tls`] connections.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] on error or an out of memory condition.
    ///
    /// # Example
    ///
    /// ```
    /// # use libtls::{config::Config, error::Result};
    /// # fn tls_config() -> Result<()> {
    /// let config = Config::new()?;
    /// #     Ok(())
    /// # }
    /// # tls_config().unwrap();
    /// ```
    ///
    /// # See also
    ///
    /// [`tls_config_new(3)`](https://man.openbsd.org/tls_config_new.3)
    ///
    /// [`Tls`]: ../tls/struct.Tls.html
    /// [`io::Error`]: https://doc.rust-lang.org/std/io/struct.Error.html
    pub fn new() -> io::Result<Self> {
        let config = unsafe { libtls_sys::tls_config_new() };
        if config.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Config(config))
        }
    }

    /// Wrap a raw C `tls_config` object.
    ///
    /// # Safety
    ///
    /// This function assumes that the raw pointer is valid, and takes
    /// ownership of the libtls object.
    /// Do not call `tls_free` yourself, since the `drop` destructor will
    /// take care of it.
    ///
    /// # Panics
    ///
    /// Panics if `config` is a null pointer.
    pub unsafe fn from_sys(config: *mut libtls_sys::tls_config) -> Self {
        if config.is_null() {
            panic!(io::Error::last_os_error())
        }
        Config(config)
    }

    /// Add additional files of a public and private key pair.
    ///
    /// The `add_keypair_file` method adds an additional public certificate, and
    /// private key from the specified files, used as an alternative certificate
    /// for Server Name Indication (server only).
    ///
    /// # Example
    ///
    /// ```
    /// # use libtls::{config::Config, error::Result};
    /// # fn tls_config() -> Result<()> {
    /// let mut config = Config::new()?;
    /// assert!(config.add_keypair_file("does_not_exist.crt", "does_not_exist.key").is_err());
    /// #     Ok(())
    /// # }
    /// # tls_config().unwrap();
    /// ```
    ///
    /// # See also
    ///
    /// [`tls_config_add_keypair_file(3)`](https://man.openbsd.org/tls_config_add_keypair_file.3)
    pub fn add_keypair_file<P: AsRef<Path>>(
        &mut self,
        cert_file: P,
        key_file: P,
    ) -> error::Result<()> {
        call_file2(
            self,
            (cert_file, "cert file"),
            (key_file, "key file"),
            libtls_sys::tls_config_add_keypair_file,
        )
    }

    /// Add an additional public and private key pair from memory.
    ///
    /// The `add_keypair_mem` method adds an additional public certificate, and
    /// private key from memory, used as an alternative certificate for Server
    /// Name Indication (server only).
    ///
    /// # Example
    ///
    /// ```
    /// # use libtls::{config::Config, error::Result};
    /// # fn tls_config() -> Result<()> {
    /// let mut config = Config::new()?;
    /// let valid_cert = include_bytes!("../tests/eccert.crt");
    /// let valid_key = include_bytes!("../tests/eccert.key");
    /// config.add_keypair_mem(valid_cert, valid_key)?;
    /// #     Ok(())
    /// # }
    /// # tls_config().unwrap();
    /// ```
    ///
    /// # See also
    ///
    /// [`tls_config_add_keypair_mem(3)`](https://man.openbsd.org/tls_config_add_keypair_mem.3)
    pub fn add_keypair_mem(&mut self, cert: &[u8], key: &[u8]) -> error::Result<()> {
        cvt(self, unsafe {
            libtls_sys::tls_config_add_keypair_mem(
                self.0,
                cert.as_ptr(),
                cert.len(),
                key.as_ptr(),
                key.len(),
            )
        })
    }

    /// Add additional files of a public and private key pair and an OCSP staple.
    ///
    /// The `add_keypair_ocsp_file` method adds an additional public certificate,
    /// private key, and DER-encoded OCSP staple from the specified files, used
    /// as an alternative certificate for Server Name Indication (server only).
    ///
    /// # See also
    ///
    /// [`add_keypair_file`](#method.add_keypair_file),
    /// [`tls_config_add_keypair_ocsp_file(3)`](https://man.openbsd.org/tls_config_add_keypair_ocsp_file.3)
    pub fn add_keypair_ocsp_file<P: AsRef<Path>>(
        &mut self,
        cert_file: P,
        key_file: P,
        ocsp_staple_file: P,
    ) -> error::Result<()> {
        call_file3(
            self,
            (cert_file, "cert file"),
            (key_file, "key file"),
            (ocsp_staple_file, "ocsp staple file"),
            libtls_sys::tls_config_add_keypair_ocsp_file,
        )
    }

    /// Add an additional public and private key pair and OCSP staple from memory.
    ///
    /// The `add_keypair_ocsp_mem` method adds an additional public certificate,
    /// private key, and DER-encoded OCSP staple from memory, used as an
    /// alternative certificate for Server Name Indication (server only).
    ///
    /// # See also
    ///
    /// [`add_keypair_mem`](#method.add_keypair_mem),
    /// [`tls_config_add_keypair_ocsp_mem(3)`](https://man.openbsd.org/tls_config_add_keypair_ocsp_mem.3)
    pub fn add_keypair_ocsp_mem(
        &mut self,
        cert: &[u8],
        key: &[u8],
        ocsp_staple: &[u8],
    ) -> error::Result<()> {
        cvt(self, unsafe {
            libtls_sys::tls_config_add_keypair_ocsp_mem(
                self.0,
                cert.as_ptr(),
                cert.len(),
                key.as_ptr(),
                key.len(),
                ocsp_staple.as_ptr(),
                ocsp_staple.len(),
            )
        })
    }

    /// Set the ALPN protocols that are supported.
    ///
    /// The `set_alpn` method sets the ALPN protocols that are supported.  The
    /// alpn string is a comma separated list of protocols, in order of
    /// preference.
    ///
    /// # Example
    ///
    /// ```
    /// # use libtls::{config::Config, error::Result};
    /// # fn tls_config() -> Result<()> {
    /// let mut config = Config::new()?;
    ///
    /// // The `h2` ALPN is used by HTTP/2:
    /// config.set_alpn("h2")?;
    /// #     Ok(())
    /// # }
    /// # tls_config().unwrap();
    /// ```
    ///
    /// # See also
    ///
    /// [`tls_config_set_alpn(3)`](https://man.openbsd.org/tls_config_set_alpn.3)
    pub fn set_alpn(&mut self, alpn: &str) -> error::Result<()> {
        call_string1(self, alpn, libtls_sys::tls_config_set_alpn)
    }

    /// Set the CA file.
    ///
    /// The `set_ca_file` method sets the filename used to load a file containing
    /// the root certificates.  The default filename can be returned with the
    /// [`default_ca_cert_file`] function.
    ///
    /// # See also
    ///
    /// [`add_keypair_file`](#method.add_keypair_file.html),
    /// [`tls_config_set_ca_file(3)`](https://man.openbsd.org/tls_config_set_ca_file.3)
    ///
    /// [`default_ca_cert_file`]: fn.default_ca_cert_file.html
    pub fn set_ca_file<P: AsRef<Path>>(&mut self, ca_file: P) -> error::Result<()> {
        call_file1(
            self,
            (ca_file, "ca file"),
            libtls_sys::tls_config_set_ca_file,
        )
    }

    /// Set the path that should be searched for the CA files.
    ///
    /// The `set_ca_path` method sets sets the path (directory) which should be
    /// searched for root certificates.
    ///
    /// # See also
    ///
    /// [`set_ca_file`](#method.set_ca_file.html),
    /// [`tls_config_set_ca_path(3)`](https://man.openbsd.org/tls_config_set_ca_path.3)
    pub fn set_ca_path<P: AsRef<Path>>(&mut self, ca_path: P) -> error::Result<()> {
        call_file1(
            self,
            (ca_path, "ca path"),
            libtls_sys::tls_config_set_ca_path,
        )
    }

    /// Set the CA from memory.
    ///
    /// The `set_ca_mem` method directly sets the root certificates directly from memory.
    ///
    ///
    /// # See also
    ///
    /// [`add_keypair_mem`](#method.add_keypair_mem),
    /// [`tls_config_set_ca_mem(3)`](https://man.openbsd.org/tls_config_set_ca_mem.3)
    pub fn set_ca_mem(&mut self, ca: &[u8]) -> error::Result<()> {
        cvt(self, unsafe {
            libtls_sys::tls_config_set_ca_mem(self.0, ca.as_ptr(), ca.len())
        })
    }

    /// Set the CA file from memory.
    ///
    /// The `set_ca_mem` method sets the root certificates directly from memory.
    ///
    /// # See also
    ///
    /// [`add_keypair_mem`](#method.add_keypair_mem.html),
    /// [`tls_config_set_ca_mem(3)`](https://man.openbsd.org/tls_config_set_ca_mem.3)
    pub fn tls_config_set_ca_mem(&mut self, ca: &[u8]) -> error::Result<()> {
        cvt(self, unsafe {
            libtls_sys::tls_config_set_ca_mem(self.0, ca.as_ptr(), ca.len())
        })
    }

    /// Set the public certificate file.
    ///
    /// The `set_cert_file` method sets file from which the public certificate
    /// will be read.
    ///
    /// # See also
    ///
    /// [`add_keypair_file`](#method.add_keypair_file),
    /// [`tls_config_set_cert_file(3)`](https://man.openbsd.org/tls_config_set_cert_file.3)
    pub fn set_cert_file<P: AsRef<Path>>(&mut self, cert_file: P) -> error::Result<()> {
        call_file1(
            self,
            (cert_file, "cert file"),
            libtls_sys::tls_config_set_cert_file,
        )
    }

    /// Set the public certificate from memory.
    ///
    /// The `set_cert_mem` method sets the public certificate directly from
    /// memory.
    ///
    /// # See also
    ///
    /// [`add_keypair_mem`](#method.add_keypair_mem),
    /// [`tls_config_set_cert_mem(3)`](https://man.openbsd.org/tls_config_set_cert_mem.3)
    pub fn set_cert_mem(&mut self, cert: &[u8]) -> error::Result<()> {
        cvt(self, unsafe {
            libtls_sys::tls_config_set_cert_mem(self.0, cert.as_ptr(), cert.len())
        })
    }

    /// Set the list of cipher that may be used.
    ///
    /// The `set_ciphers` method sets the list of ciphers that may be used.
    /// Lists of ciphers are specified by name, and the permitted names are:
    ///
    /// * `secure` (or alias `default`)
    /// * `compat`
    /// * `legacy`
    /// * `insecure` (or alias `all`)
    ///
    /// Alternatively, libssl cipher strings can be specified.  See the CIPHERS
    /// section of [`openssl(1)`] for further information.
    ///
    /// # Example
    ///
    /// ```
    /// # use libtls::{config::Config, error::Result};
    /// # fn tls_config() -> Result<()> {
    /// let mut config = Config::new()?;
    ///
    /// // Only use `compat` if you run into problems with the `secure` default!
    /// config.set_ciphers("compat")?;
    /// #     Ok(())
    /// # }
    /// # tls_config().unwrap();
    /// ```
    ///
    /// # See also
    ///
    /// [`openssl(1)`],
    /// [`tls_config_set_ciphers(3)`](https://man.openbsd.org/tls_config_set_ciphers.3)
    ///
    /// [`openssl(1)`]: http://man.openbsd.org/openssl.1#CIPHERS
    pub fn set_ciphers(&mut self, ciphers: &str) -> error::Result<()> {
        call_string1(self, ciphers, libtls_sys::tls_config_set_ciphers)
    }

    /// Set the CRL file.
    ///
    /// The `set_crl_file` method sets the filename used to load a file
    /// containing the Certificate Revocation List (CRL).
    ///
    /// # See also
    ///
    /// [`add_keypair_file`](#method.add_keypair_file.html),
    /// [`tls_config_set_crl_file(3)`](https://man.openbsd.org/tls_config_set_crl_file.3)
    pub fn set_crl_file<P: AsRef<Path>>(&mut self, crl_file: P) -> error::Result<()> {
        call_file1(
            self,
            (crl_file, "crl file"),
            libtls_sys::tls_config_set_crl_file,
        )
    }

    /// Set the CRL from memory.
    ///
    /// The `set_crl_mem` method sets the Certificate Revocation List (CRL)
    /// directly from memory.
    ///
    /// # See also
    ///
    /// [`add_keypair_mem`](#method.add_keypair_mem.html),
    /// [`tls_config_set_crl_mem(3)`](https://man.openbsd.org/tls_config_set_crl_mem.3)
    pub fn set_crl_mem(&mut self, crl: &[u8]) -> error::Result<()> {
        cvt(self, unsafe {
            libtls_sys::tls_config_set_crl_mem(self.0, crl.as_ptr(), crl.len())
        })
    }

    /// Set the parameters of an Diffie-Hellman Ephemeral (DHE) key exchange.
    ///
    /// The `set_dheparams` method specifies the parameters that will be used
    /// during Diffie-Hellman Ephemeral (DHE) key exchange.  Possible values are
    /// `none`, `auto` and `legacy`.  In `auto` mode, the key size for the
    /// ephemeral key is automatically selected based on the size of the private
    /// key being used for signing.  In `legacy` mode, 1024 bit ephemeral keys
    /// are used.  The default value is `none`, which disables DHE key exchange.
    ///
    /// # Example
    ///
    /// ```
    /// # use libtls::{config::Config, error::Result};
    /// # fn tls_config() -> Result<()> {
    /// let mut config = Config::new()?;
    /// config.set_dheparams("auto")?;
    /// #     Ok(())
    /// # }
    /// # tls_config().unwrap();
    /// ```
    ///
    /// # See also
    ///
    /// [`tls_config_set_dheparams(3)`](https://man.openbsd.org/tls_config_set_dheparams.3)
    pub fn set_dheparams(&mut self, dheparams: &str) -> error::Result<()> {
        call_string1(self, dheparams, libtls_sys::tls_config_set_dheparams)
    }

    /// The `set_ecdhecurve` method was replaced by [set_ecdhecurves](#method.set_ecdhecurves).
    #[deprecated(
        since = "2.6.1-LibreSSL",
        note = "Replaced by [set_ecdhecurves](#method.set_ecdhecurves)."
    )]
    pub fn set_ecdhecurve(&mut self, ecdhecurve: &str) -> error::Result<()> {
        call_string1(self, ecdhecurve, libtls_sys::tls_config_set_ecdhecurve)
    }

    /// Set the curves of an Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) key exchange.
    ///
    /// The `set_ecdhecurves` method specifies the names of the elliptic curves
    /// that may be used during Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)
    /// key exchange.  This is a comma separated list, given in order of
    /// preference.  The special value of "default" will use the default curves
    /// (currently X25519, P-256 and P-384).  This function replaces
    /// [`set_ecdhecurve`], which is deprecated.
    ///
    /// # Example
    ///
    /// ```
    /// # use libtls::{config::Config, error::Result};
    /// # fn tls_config() -> Result<()> {
    /// let mut config = Config::new()?;
    /// config.set_ecdhecurves("X25519,P-384")?;
    /// #     Ok(())
    /// # }
    /// # tls_config().unwrap();
    /// ```
    ///
    /// # See also
    ///
    /// [`tls_config_set_ecdhecurves(3)`](https://man.openbsd.org/tls_config_set_ecdhecurves.3)
    ///
    /// [`set_ecdhecurve`]: #method.set_ecdhecurve
    pub fn set_ecdhecurves(&mut self, ecdhecurves: &str) -> error::Result<()> {
        call_string1(self, ecdhecurves, libtls_sys::tls_config_set_ecdhecurves)
    }

    /// Set the private key file.
    ///
    /// The `set_key_file` method sets the file from which the private key will
    /// be read.
    ///
    /// # See also
    ///
    /// [`add_keypair_file`](#method.add_keypair_file),
    /// [`tls_config_set_key_file(3)`](https://man.openbsd.org/tls_config_set_key_file.3)
    pub fn set_key_file<P: AsRef<Path>>(&mut self, key_file: P) -> error::Result<()> {
        call_file1(
            self,
            (key_file, "key file"),
            libtls_sys::tls_config_set_key_file,
        )
    }

    /// Set the private key from memory.
    ///
    /// The `set_key_mem` method directly sets the private key from memory.
    ///
    /// # See also
    ///
    /// [`add_keypair_mem`](#method.add_keypair_mem),
    /// [`tls_config_set_key_mem(3)`](https://man.openbsd.org/tls_config_set_key_mem.3)
    pub fn set_key_mem(&mut self, key: &[u8]) -> error::Result<()> {
        cvt(self, unsafe {
            libtls_sys::tls_config_set_key_mem(self.0, key.as_ptr(), key.len())
        })
    }

    /// Set the files of the public and private key pair.
    ///
    /// The `set_keypair_file` method sets the files from which the public
    /// certificate, and private key will be read.
    ///
    /// # See also
    ///
    /// [`add_keypair_file`](#method.add_keypair_file),
    /// [`tls_config_set_keypair_file(3)`](https://man.openbsd.org/tls_config_set_keypair_file.3)
    pub fn set_keypair_file<P: AsRef<Path>>(
        &mut self,
        cert_file: P,
        key_file: P,
    ) -> error::Result<()> {
        call_file2(
            self,
            (cert_file, "cert file"),
            (key_file, "key file"),
            libtls_sys::tls_config_set_keypair_file,
        )
    }

    /// Set the public and private key pair from memory.
    ///
    /// The `set_keypair_mem` method directly sets the public certificate, and
    /// private key from memory.
    ///
    /// # See also
    ///
    /// [`add_keypair_mem`](#method.add_keypair_mem),
    /// [`tls_config_set_keypair_mem(3)`](https://man.openbsd.org/tls_config_set_keypair_mem.3)
    pub fn set_keypair_mem(&mut self, cert: &[u8], key: &[u8]) -> error::Result<()> {
        cvt(self, unsafe {
            libtls_sys::tls_config_set_keypair_mem(
                self.0,
                cert.as_ptr(),
                cert.len(),
                key.as_ptr(),
                key.len(),
            )
        })
    }

    /// Set the files of a public and private key pair and an OCSP staple.
    ///
    /// The `set_keypair_ocsp_file` method sets the public certificate,
    /// private key, and DER-encoded OCSP staple from the specified files.
    ///
    /// # See also
    ///
    /// [`add_keypair_ocsp_file`](#method.add_keypair_ocsp_file),
    /// [`tls_config_set_keypair_ocsp_file(3)`](https://man.openbsd.org/tls_config_set_keypair_ocsp_file.3)
    pub fn set_keypair_ocsp_file<P: AsRef<Path>>(
        &mut self,
        cert_file: P,
        key_file: P,
        ocsp_staple_file: P,
    ) -> error::Result<()> {
        call_file3(
            self,
            (cert_file, "cert file"),
            (key_file, "key file"),
            (ocsp_staple_file, "ocsp staple file"),
            libtls_sys::tls_config_set_keypair_ocsp_file,
        )
    }

    /// Set the public and private key pair and an OCSP staple from memory.
    ///
    /// The `set_keypair_ocsp_mem` method sets the public certificate,
    /// private key, and DER-encoded OCSP staple directly from memory.
    ///
    /// # See also
    ///
    /// [`add_keypair_ocsp_mem`](#method.add_keypair_ocsp_mem),
    /// [`tls_config_set_keypair_ocsp_mem(3)`](https://man.openbsd.org/tls_config_set_keypair_ocsp_mem.3)
    pub fn set_keypair_ocsp_mem(
        &mut self,
        cert: &[u8],
        key: &[u8],
        ocsp_staple: &[u8],
    ) -> error::Result<()> {
        cvt(self, unsafe {
            libtls_sys::tls_config_set_keypair_ocsp_mem(
                self.0,
                cert.as_ptr(),
                cert.len(),
                key.as_ptr(),
                key.len(),
                ocsp_staple.as_ptr(),
                ocsp_staple.len(),
            )
        })
    }

    /// Set the OCSP staple from memory.
    ///
    /// The `set_keypair_ocsp_mem` method sets a DER-encoded OCSP response to be
    /// stapled during the TLS handshake from memory.
    ///
    /// # See also
    ///
    /// [`add_keypair_mem`](#method.add_keypair_mem),
    /// [`tls_config_set_ocsp_staple_mem(3)`](https://man.openbsd.org/tls_config_set_ocsp_staple_mem.3)
    pub fn set_ocsp_staple_mem(&mut self, ocsp_staple: &[u8]) -> error::Result<()> {
        cvt(self, unsafe {
            libtls_sys::tls_config_set_ocsp_staple_mem(
                self.0,
                ocsp_staple.as_ptr(),
                ocsp_staple.len(),
            )
        })
    }

    /// Set the OCSP staple file.
    ///
    /// The `set_keypair_ocsp_mem` method sets a DER-encoded OCSP response to be
    /// stapled during the TLS handshake from the specified file.
    ///
    ///
    /// # See also
    ///
    /// [`add_keypair_file`](#method.add_keypair_file),
    /// [`tls_config_set_ocsp_staple_file(3)`](https://man.openbsd.org/tls_config_set_ocsp_staple_file.3)
    pub fn set_ocsp_staple_file<P: AsRef<Path>>(
        &mut self,
        ocsp_staple_file: P,
    ) -> error::Result<()> {
        call_file1(
            self,
            (ocsp_staple_file, "ocsp staple file"),
            libtls_sys::tls_config_set_ocsp_staple_file,
        )
    }

    /// Set which versions of the TLS protocol may be used.
    ///
    /// The `set_protocols` method specifies which versions of the TLS protocol
    /// may be used.  Possible values are the bitwise OR of:
    ///
    /// * [`TLS_PROTOCOL_TLSv1_0`]
    /// * [`TLS_PROTOCOL_TLSv1_1`]
    /// * [`TLS_PROTOCOL_TLSv1_2`]
    ///
    /// Additionally, the values [`TLS_PROTOCOL_TLSv1`] (TLSv1.0, TLSv1.1 and
    /// TLSv1.2), [`TLS_PROTOCOLS_ALL`] (all supported protocols) and
    /// [`TLS_PROTOCOLS_DEFAULT`] (TLSv1.2 only) may be used.
    ///
    /// # Example
    ///
    /// ```
    /// # use libtls::{config::{self, Config}, error::Result};
    /// # fn tls_config() -> Result<()> {
    /// let mut config = Config::new()?;
    /// let protocols = config::parse_protocols("tlsv1.1,tlsv1.2")?;
    /// config.set_protocols(protocols)?;
    /// #    Ok(())
    /// # }
    /// # tls_config().unwrap();
    /// ```
    ///
    /// # See also
    ///
    /// [`parse_protocols`](fn.parse_protocols.html),
    /// [`tls_config_set_protocols(3)`](https://man.openbsd.org/tls_config_set_protocols.3)
    ///
    /// [`TLS_PROTOCOLS_ALL`]: ../constant.TLS_PROTOCOLS_ALL.html
    /// [`TLS_PROTOCOLS_DEFAULT`]: ../constant.TLS_PROTOCOLS_DEFAULT.html
    /// [`TLS_PROTOCOL_TLSv1`]: ../constant.TLS_PROTOCOL_TLSv1.html
    /// [`TLS_PROTOCOL_TLSv1_0`]: ../constant.TLS_PROTOCOL_TLSv1_0.html
    /// [`TLS_PROTOCOL_TLSv1_1`]: ../constant.TLS_PROTOCOL_TLSv1_1.html
    /// [`TLS_PROTOCOL_TLSv1_2`]: ../constant.TLS_PROTOCOL_TLSv1_2.html
    pub fn set_protocols(&mut self, protocols: u32) -> error::Result<()> {
        call_arg1(self, protocols, libtls_sys::tls_config_set_protocols)
    }

    /// Set a file descriptor to manage data for TLS sessions.
    ///
    /// The `set_session_fd` method sets a file descriptor to be used to manage
    /// data for TLS sessions (client only).  The given file descriptor must be a
    /// regular file and be owned by the current user, with permissions being
    /// restricted to only allow the owner to read and write the file (0600).  If
    /// the file has a non-zero length, the client will attempt to read session
    /// data from this file and resume the previous TLS session with the server.
    /// Upon a successful handshake the file will be updated with current session
    /// data, if available.  The caller is responsible for closing this file
    /// descriptor, after all [`TLS`] contexts that have been configured to use it
    /// have been [dropped].
    ///
    /// # See also
    ///
    /// [`tls_config_set_session_fd(3)`](https://man.openbsd.org/tls_config_set_session_fd.3)
    ///
    /// [`Tls`]: ../tls/struct.Tls.html
    /// [dropped]: ../tls/struct.Tls.html#impl-Drop
    pub fn set_session_fd(&mut self, session_fd: RawFd) -> error::Result<()> {
        call_arg1(self, session_fd, libtls_sys::tls_config_set_session_fd)
    }

    /// Set the certificate verification depth.
    ///
    /// The `set_verify_depth` method limits the number of intermediate
    /// certificates that will be followed during certificate validation.
    ///
    /// # See also
    ///
    /// [`tls_config_set_verify_depth(3)`](https://man.openbsd.org/tls_config_set_verify_depth.3)
    pub fn set_verify_depth(&mut self, verify_depth: usize) -> error::Result<()> {
        call_arg1(
            self,
            verify_depth as i32,
            libtls_sys::tls_config_set_verify_depth,
        )
    }

    /// Prefer ciphers in the client's cipher list.
    ///
    /// The `prefer_ciphers_client` method prefers ciphers in the client's cipher
    /// list when selecting a cipher suite (server only).  This is considered to
    /// be less secure than preferring the server's list.
    ///
    /// # See also
    ///
    /// [`tls_config_prefer_ciphers_client(3)`](https://man.openbsd.org/tls_config_prefer_ciphers_client.3)
    pub fn prefer_ciphers_client(&mut self) {
        unsafe { libtls_sys::tls_config_prefer_ciphers_client(self.0) }
    }

    /// Prefer ciphers in the servers's cipher list.
    ///
    /// The `prefer_ciphers_server` method prefers ciphers in the server's cipher
    /// list when selecting a cipher suite (server only).  This is considered to
    /// be more secure than preferring the client's list and is the default.
    ///
    /// # See also
    ///
    /// [`tls_config_prefer_ciphers_server(3)`](https://man.openbsd.org/tls_config_prefer_ciphers_server.3)
    pub fn prefer_ciphers_server(&mut self) {
        unsafe { libtls_sys::tls_config_prefer_ciphers_server(self.0) }
    }

    /// Disable certificate verification.
    ///
    /// The `insecure_noverifycert` method disables certificate verification and
    /// OCSP validation.
    ///
    /// # See also
    ///
    /// [`tls_config_insecure_noverifycert(3)`](https://man.openbsd.org/tls_config_insecure_noverifycert.3)
    pub fn insecure_noverifycert(&mut self) {
        unsafe { libtls_sys::tls_config_insecure_noverifycert(self.0) }
    }

    /// Disable server name verification.
    ///
    /// The `insecure_noverifyname` method disables server name verification
    /// (client only).
    ///
    /// # See also
    ///
    /// [`tls_config_insecure_noverifyname(3)`](https://man.openbsd.org/tls_config_insecure_noverifyname.3)
    pub fn insecure_noverifyname(&mut self) {
        unsafe { libtls_sys::tls_config_insecure_noverifyname(self.0) }
    }

    /// Disable certificate validity checking.
    ///
    /// The `insecure_noverifytime` method disables validity checking of
    /// certificates and OCSP validation.
    ///
    /// # See also
    ///
    /// [`tls_config_insecure_noverifytime(3)`](https://man.openbsd.org/tls_config_insecure_noverifytime.3)
    pub fn insecure_noverifytime(&mut self) {
        unsafe { libtls_sys::tls_config_insecure_noverifytime(self.0) }
    }

    /// Enable all certificate verification.
    ///
    /// The `verify` method reenables server name and certificate verification.
    ///
    /// # See also
    ///
    /// [`tls_config_verify(3)`](https://man.openbsd.org/tls_config_verify.3)
    pub fn verify(&mut self) {
        // reenables OCSP validation as well?
        unsafe { libtls_sys::tls_config_verify(self.0) }
    }

    /// Require OCSP stapling.
    ///
    /// The `ocsp_require_stapling` method requires that a valid stapled OCSP
    /// response be provided during the TLS handshake.
    ///
    /// # See also
    ///
    /// [`tls_config_ocsp_require_stapling(3)`](https://man.openbsd.org/tls_config_ocsp_require_stapling.3)
    pub fn ocsp_require_stapling(&mut self) {
        unsafe { libtls_sys::tls_config_ocsp_require_stapling(self.0) }
    }

    /// Enable client certificate verification.
    ///
    /// The `verify_client` method enables client certificate verification,
    /// requiring the client to send a certificate (server only).
    ///
    /// # See also
    ///
    /// [`tls_config_verify_client(3)`](https://man.openbsd.org/tls_config_verify_client.3)
    pub fn verify_client(&mut self) {
        unsafe { libtls_sys::tls_config_verify_client(self.0) }
    }

    /// Enable optional client certificate verification.
    ///
    /// The `verify_client_optional` method enables client certificate
    /// verification, without requiring the client to send a certificate (server
    /// only).
    ///
    /// # See also
    ///
    /// [`tls_config_verify_client_optional(3)`](https://man.openbsd.org/tls_config_verify_client_optional.3)
    pub fn verify_client_optional(&mut self) {
        unsafe { libtls_sys::tls_config_verify_client_optional(self.0) }
    }

    /// Securely clear secret keys.
    ///
    /// The `clear_keys` method clears any secret keys from memory.
    ///
    /// # See also
    ///
    /// [`tls_config_clear_keys(3)`](https://man.openbsd.org/tls_config_clear_keys.3)
    pub fn clear_keys(&mut self) {
        unsafe { libtls_sys::tls_config_clear_keys(self.0) }
    }

    /// Set the session identifier for TLS sessions.
    ///
    /// The `set_session_id` method sets the session identifier that will be used
    /// by the TLS server when sessions are enabled (server only).  By default a
    /// random value is used.
    ///
    /// # Example
    ///
    /// ```
    /// # use libtls::{config::Config, error::Result, *};
    /// # use rand::{thread_rng, Rng};
    /// # fn tls_config() -> Result<()> {
    /// let mut session_id = [0; TLS_MAX_SESSION_ID_LENGTH as usize];
    /// thread_rng().fill(&mut session_id[..]);
    ///
    /// let mut config = Config::new()?;
    /// config.set_session_id(&session_id[..])?;
    /// #     Ok(())
    /// # }
    /// # tls_config().unwrap();
    /// ```
    ///
    /// # See also
    ///
    /// [`tls_config_set_session_id(3)`](https://man.openbsd.org/tls_config_set_session_id.3)
    pub fn set_session_id(&mut self, session_id: &[u8]) -> error::Result<()> {
        cvt(self, unsafe {
            libtls_sys::tls_config_set_session_id(self.0, session_id.as_ptr(), session_id.len())
        })
    }

    /// Set the lifetime for TLS sessions.
    ///
    /// The `set_session_lifetime` method sets the lifetime to be used for TLS
    /// sessions (server only).  Session support is disabled if a lifetime of
    /// zero is specified, which is the default.
    ///
    /// # See also
    ///
    /// [`tls_config_set_session_lifetime(3)`](https://man.openbsd.org/tls_config_set_session_lifetime.3)
    pub fn set_session_lifetime(&mut self, lifetime: usize) -> error::Result<()> {
        call_arg1(
            self,
            lifetime as i32,
            libtls_sys::tls_config_set_session_lifetime,
        )
    }

    /// Add a key for the encryption and authentication of TLS tickets.
    ///
    /// The `add_ticket_key` method adds a key used for the encryption and
    /// authentication of TLS tickets (server only).  By default keys are
    /// generated and rotated automatically based on their lifetime.  This
    /// function should only be used to synchronise ticket encryption key across
    /// multiple processes.  Re-adding a known key will result in an error,
    /// unless it is the most recently added key.
    ///
    /// # Example
    ///
    /// ```
    /// # use libtls::{config::Config, error::Result, *};
    /// # use rand::{thread_rng, Rng};
    /// # fn tls_config() -> Result<()> {
    /// let mut key = [0; TLS_TICKET_KEY_SIZE as usize];
    /// thread_rng().fill(&mut key[..]);
    ///
    /// let mut config = Config::new()?;
    /// config.add_ticket_key(1, &mut key[..])?;
    /// #     Ok(())
    /// # }
    /// # tls_config().unwrap();
    /// ```
    ///
    /// # See also
    ///
    /// [`tls_config_add_ticket_key(3)`](https://man.openbsd.org/tls_config_add_ticket_key.3)
    pub fn add_ticket_key(&mut self, keyrev: u32, key: &mut [u8]) -> error::Result<()> {
        // XXX key should be const, consider changing this in the upstream API
        cvt(self, unsafe {
            libtls_sys::tls_config_add_ticket_key(self.0, keyrev, key.as_mut_ptr(), key.len())
        })
    }
}

impl error::LastError for Config {
    /// Returns the configuration last error.
    ///
    /// The `last_error` method returns an error if no error occurred with config
    /// at all, or if memory allocation failed while trying to assemble the
    /// string describing the most recent error related to config.
    ///
    /// # See also
    ///
    /// [`tls_config_error(3)`](https://man.openbsd.org/tls_config_error.3)
    fn last_error(&self) -> error::Result<String> {
        unsafe { cvt_no_error(libtls_sys::tls_config_error(self.0)) }
    }

    fn to_error<T>(errstr: String) -> error::Result<T> {
        Err(error::Error::ConfigError(errstr))
    }
}

impl Drop for Config {
    /// Free the configuration object.  This should only happen when no
    /// more [`Tls`] contexts are to be configured.
    ///
    /// # See also
    ///
    /// [`tls_config_free(3)`](https://man.openbsd.org/tls_config_free.3)
    ///
    /// [`Tls`]: ../tls/struct.Tls.html
    fn drop(&mut self) {
        unsafe { libtls_sys::tls_config_free(self.0) };
    }
}

unsafe impl Send for Config {}
unsafe impl Sync for Config {}

/// Return path of the default CA file.
///
/// The `default_ca_cert_file` utility function returns the path of the file that
/// contains the default root certificates.
///
/// # Example
///
/// ```
/// # use libtls::config;
/// let certs = config::default_ca_cert_file();
/// assert!(certs.is_absolute());
/// ```
///
/// # See also
///
/// [`tls_default_ca_cert_file(3)`](https://man.openbsd.org/tls_default_ca_cert_file.3)
pub fn default_ca_cert_file() -> PathBuf {
    unsafe { CStr::from_ptr(libtls_sys::tls_default_ca_cert_file()) }
        .to_string_lossy()
        .into_owned()
        .into()
}

/// Parse protocol string.
///
/// The `tls_config_parse_protocols` utility function parses a protocol
/// string and returns the corresponding value via the protocols argument.
/// This value can then be passed to the [`set_protocols`] method.
/// The protocol string is a comma or colon separated list of keywords.
/// Valid keywords are `tlsv1.0`, `tlsv1.1`, `tlsv1.2`, `all` (all supported
/// protocols), `default` (an alias for secure), `legacy` (an alias for all) and
/// `secure` (currently TLSv1.2 only).  If a value has a negative prefix (in
/// the form of a leading exclamation mark) then it is removed from the list
/// of available protocols, rather than being added to it.
///
/// # Example
///
/// ```
/// # use libtls::{config::Config, error::Result, *};
/// # fn tls_config() -> Result<()> {
/// // Parse a list of allowed protocols:
/// let protocols = config::parse_protocols("tlsv1.1,tlsv1.2").unwrap();
/// assert_eq!(protocols, TLS_PROTOCOL_TLSv1_1|TLS_PROTOCOL_TLSv1_2);
///
/// // The default is to use the `secure` protocols, currently TLSv1.2 only:
/// let protocols = config::parse_protocols("default").unwrap();
/// assert_eq!(protocols, TLS_PROTOCOL_TLSv1_2);
/// #     Ok(())
/// # }
/// # tls_config().unwrap();
/// ```
///
/// # See also
///
/// [`tls_config_parse_protocols(3)`](https://man.openbsd.org/tls_config_parse_protocols.3)
///
/// [`set_protocols`]: #method.set_protocols
pub fn parse_protocols(protostr: &str) -> error::Result<u32> {
    let c_protostr = CString::new(protostr)?;
    let mut protocols: u32 = 0;

    let retval =
        unsafe { libtls_sys::tls_config_parse_protocols(&mut protocols, c_protostr.as_ptr()) };
    if retval == -1 {
        Err(io::Error::new(io::ErrorKind::Other, "Invalid protocols string").into())
    } else {
        Ok(protocols)
    }
}

/// Load a certificate or key file.
///
/// The `load_file` function loads a certificate or key from disk into memory
/// to be used with [`set_ca_mem`], [`set_cert_mem`], [`set_crl_mem`] or
/// [`set_key_mem`].  A private key will be decrypted if the optional password
/// argument is specified.
///
/// # Example
///
/// ```
/// # use libtls::{config, error::Result};
/// # fn tls_config() -> Result<()> {
/// # let filename = file!();
/// let data = config::load_file(filename, None)?;
/// config::unload_file(data);
/// #     Ok(())
/// # }
/// # tls_config().unwrap();
/// ```
///
/// # See also
///
/// [`unload_file`],
/// [`tls_load_file(3)`](https://man.openbsd.org/tls_load_file.3)
///
/// [`set_ca_mem`]: struct.Config.html#method.set_ca_mem
/// [`set_cert_mem`]: struct.Config.html#method.set_cert_mem
/// [`set_crl_mem`]: struct.Config.html#method.set_crl_mem
/// [`set_key_mem`]: struct.Config.html#method.set_key_mem
/// [`unload_file`]: fn.unload_file.html
pub fn load_file<P: AsRef<Path>>(file: P, password: Option<&str>) -> error::Result<Vec<u8>> {
    let mut size = 0;
    let s_file = cvt_option(
        file.as_ref().to_str(),
        io::Error::new(io::ErrorKind::InvalidInput, "file"),
    )?;
    unsafe {
        let c_file = CString::new(s_file)?;
        let data = match password {
            Some(password) => {
                let c_password = CString::new(password)?;

                let raw = c_password.into_raw();
                let data = libtls_sys::tls_load_file(c_file.as_ptr(), &mut size, raw);

                // Make sure that the raw pointer is not leaked
                let _ = CString::from_raw(raw);

                data
            }
            None => libtls_sys::tls_load_file(c_file.as_ptr(), &mut size, std::ptr::null_mut()),
        };
        if data.is_null() {
            Err(io::Error::last_os_error().into())
        } else {
            Ok(Vec::from_raw_parts(data, size, size))
        }
    }
}

/// Securely unload file that was loaded into memory.
///
/// The `unload_file` function unloads the memory that was returned from an
/// earlier [`load_file`] call, ensuring that the memory contents is discarded.
///
/// # See also
///
/// [`tls_unload_file(3)`](https://man.openbsd.org/tls_unload_file.3)
///
/// [`load_file`]: fn.load_file.html
pub fn unload_file(mut data: Vec<u8>) {
    let ptr = data.as_mut_ptr();
    let len = data.len();
    std::mem::forget(data);
    unsafe { libtls_sys::tls_unload_file(ptr, len) }
}

#[derive(Debug, Clone)]
enum KeyData {
    File(PathBuf),
    Path(PathBuf),
    KeyPairFiles(PathBuf, PathBuf, Option<PathBuf>),
    KeyPairMem(Vec<u8>, Vec<u8>, Option<Vec<u8>>),
    Mem(Vec<u8>),
}

/// `Builder` for [`Config`].
///
/// # Example
///
/// ```
/// # use libtls::{config::Builder, error::Result};
/// # use libtls_sys::*;
/// # fn tls_config() -> Result<()> {
/// #     let key = include_bytes!("../tests/eccert.key");
/// #     let cert = include_bytes!("../tests/eccert.crt");
/// #     let ticket_key1 = [0; TLS_TICKET_KEY_SIZE as usize];
/// #     let ticket_key2 = [0; TLS_TICKET_KEY_SIZE as usize];
/// let mut config = Builder::new()
///     .keypair_mem(cert, key, None)
///     .ticket_key(1, &ticket_key1)
///     .ticket_key(2, &ticket_key2)
///     .protocols(TLS_PROTOCOLS_ALL)
///     .ecdhecurves("X25519")
///     .alpn("h2")
///     .build()?;
/// #     Ok(())
/// # }
/// # tls_config().unwrap();
/// ```
///
/// [`Config`]: struct.Config.html
#[derive(Default, Debug, Clone)]
pub struct Builder {
    alpn: Option<String>,
    ca: Option<KeyData>,
    ciphers: Option<String>,
    crl: Option<KeyData>,
    dheparams: Option<String>,
    ecdhecurves: Option<String>,
    keypairs: Vec<KeyData>,
    noverifycert: bool,
    noverifyname: bool,
    noverifytime: bool,
    protocols: Option<u32>,
    session_fd: Option<RawFd>,
    session_id: Option<Vec<u8>>,
    session_lifetime: Option<usize>,
    ticket_key: HashMap<u32, Vec<u8>>,
    verify: bool,
    verify_client: bool,
    verify_client_optional: bool,
    verify_depth: Option<usize>,
}

/// `TlsConfigBuilder` for [`TlsConfig`].
#[deprecated(
    since = "1.1.1",
    note = "Please use `Builder` instead of `TlsConfigBuilder`"
)]
pub type TlsConfigBuilder = Builder;

impl Builder {
    /// Return new `Builder`.
    ///
    /// # See also
    ///
    /// [`Config`](struct.Config.html)
    pub fn new() -> Self {
        Default::default()
    }

    /// Build new [`Config`] object.
    ///
    /// # See also
    ///
    /// [`Config`]
    ///
    /// [`Config`]: struct.Config.html
    pub fn build(&self) -> error::Result<Config> {
        let mut config = Config::new()?;

        // First add the keypairs and optional OCSP staples.
        self.build_keypairs(&mut config)?;

        // Now all the other settings
        if let Some(ref alpn) = self.alpn {
            config.set_alpn(alpn)?;
        }
        if let Some(ref ca) = self.ca {
            match ca {
                KeyData::Mem(mem) => config.set_ca_mem(mem)?,
                KeyData::File(file) => config.set_ca_file(file)?,
                KeyData::Path(path) => config.set_ca_path(path)?,
                _ => return Err(error::Error::NoError),
            };
        } else if !default_ca_cert_file().exists() {
            // Try to use the default CA path as a fallback.
            config.set_ca_path("/etc/ssl/certs")?;
        };
        if let Some(ref ciphers) = self.ciphers {
            config.set_ciphers(ciphers)?;
        }
        if let Some(ref crl) = self.crl {
            match crl {
                KeyData::Mem(mem) => config.set_ca_mem(mem)?,
                KeyData::File(file) => config.set_ca_file(file)?,
                _ => return Err(error::Error::NoError),
            };
        }
        if let Some(ref dheparams) = self.dheparams {
            config.set_dheparams(dheparams)?;
        }
        if let Some(ref ecdhecurves) = self.ecdhecurves {
            config.set_ecdhecurves(ecdhecurves)?;
        }
        if let Some(protocols) = self.protocols {
            config.set_protocols(protocols)?;
        }
        if let Some(session_fd) = self.session_fd {
            config.set_session_fd(session_fd)?;
        }
        if let Some(ref session_id) = self.session_id {
            config.set_session_id(session_id)?;
        }
        if let Some(session_lifetime) = self.session_lifetime {
            config.set_session_lifetime(session_lifetime)?;
        }

        // Add ticket keys
        for (keyrev, key) in self.ticket_key.iter() {
            // The tls_ticket_key() API is "broken" as it requires the key
            // as mut and not const.
            config.add_ticket_key(*keyrev, key.clone().as_mut_slice())?;
        }

        // Order verify_* calls in a safe priority.
        if self.noverifycert {
            config.insecure_noverifycert();
        }
        if self.noverifyname {
            config.insecure_noverifyname();
        }
        if self.noverifytime {
            config.insecure_noverifytime();
        }
        if let Some(verify_depth) = self.verify_depth {
            config.set_verify_depth(verify_depth)?;
        }
        if self.verify_client_optional {
            config.verify_client_optional();
        }
        if self.verify_client {
            config.verify_client();
        }
        if self.verify {
            config.verify();
        }

        Ok(config)
    }

    fn build_keypairs(&self, config: &mut Config) -> error::Result<()> {
        for (i, kp) in self.keypairs.iter().enumerate() {
            match kp {
                KeyData::KeyPairMem(cert, key, ocsp) => {
                    if let Some(ocsp) = ocsp {
                        // Set the first keypair as the default.
                        if i == 0 {
                            config.set_keypair_ocsp_mem(cert, key, ocsp)?;
                        }
                        config.add_keypair_ocsp_mem(cert, key, ocsp)?;
                    } else {
                        if i == 0 {
                            config.set_keypair_mem(cert, key)?;
                        }
                        config.add_keypair_mem(cert, key)?;
                    }
                }
                KeyData::KeyPairFiles(cert, key, ocsp) => {
                    if let Some(ocsp) = ocsp {
                        if i == 0 {
                            config.set_keypair_ocsp_file(cert, key, ocsp)?;
                        }
                        config.add_keypair_ocsp_file(cert, key, ocsp)?;
                    } else {
                        if i == 0 {
                            config.set_keypair_file(cert, key)?;
                        }
                        config.add_keypair_file(cert, key)?;
                    }
                }
                _ => return Err(error::Error::NoError),
            };
        }

        Ok(())
    }

    /// Build new [`Config`] object and return a configured [`Tls`] client.
    ///
    /// # See also
    ///
    /// [`Tls`],
    /// [`Config`]
    ///
    /// [`Tls`]: ../tls/struct.Tls.html
    /// [`Config`]: struct.Config.html
    pub fn client(&self) -> error::Result<Tls> {
        let mut client = Tls::client()?;
        client.configure(&self.build()?)?;
        Ok(client)
    }

    /// Build new [`Config`] object and return a configured [`Tls`] server.
    ///
    /// # See also
    ///
    /// [`Tls`],
    /// [`Config`]
    ///
    /// [`Tls`]: ../tls/struct.Tls.html
    /// [`Config`]: struct.Config.html
    pub fn server(&self) -> error::Result<Tls> {
        let mut server = Tls::server()?;
        server.configure(&self.build()?)?;
        Ok(server)
    }

    /// Set the ALPN protocols that are supported.
    ///
    /// # See also
    ///
    /// [`Config::set_alpn`](struct.Config.html#method.set_alpn)
    pub fn alpn(&'_ mut self, alpn: &str) -> &'_ mut Self {
        self.alpn = Some(alpn.to_owned());
        self
    }

    /// Set the CA file.
    ///
    /// # See also
    ///
    /// [`Config::set_ca_file`](struct.Config.html#method.set_ca_file)
    pub fn ca_file<P: AsRef<Path>>(&'_ mut self, path: P) -> &'_ mut Self {
        self.ca = Some(KeyData::File(path.as_ref().to_owned()));
        self
    }

    /// Set the CA path.
    ///
    /// # See also
    ///
    /// [`Config::set_ca_path`](struct.Config.html#method.set_ca_path)
    pub fn ca_path<P: AsRef<Path>>(&'_ mut self, path: P) -> &'_ mut Self {
        self.ca = Some(KeyData::Path(path.as_ref().to_owned()));
        self
    }

    /// Set the CA from memory.
    ///
    /// # See also
    ///
    /// [`Config::set_ca_mem`](struct.Config.html#method.set_ca_mem)
    pub fn ca_mem(&'_ mut self, mem: &[u8]) -> &'_ mut Self {
        self.ca = Some(KeyData::Mem(mem.to_vec()));
        self
    }

    /// Set the list of cipher that may be used.
    ///
    /// # See also
    ///
    /// [`Config::set_ciphers`](struct.Config.html#method.set_ciphers)
    pub fn ciphers(&'_ mut self, ciphers: &str) -> &'_ mut Self {
        self.ciphers = Some(ciphers.to_owned());
        self
    }

    /// Set the CRL file.
    ///
    /// # See also
    ///
    /// [`Config::set_crl_file`](struct.Config.html#method.set_crl_file)
    pub fn crl_file<P: AsRef<Path>>(&'_ mut self, path: P) -> &'_ mut Self {
        self.crl = Some(KeyData::File(path.as_ref().to_owned()));
        self
    }

    /// Set the CRL from memory.
    ///
    /// # See also
    ///
    /// [`Config::set_crl_mem`](struct.Config.html#method.set_crl_mem)
    pub fn crl_mem(&'_ mut self, mem: &[u8]) -> &'_ mut Self {
        self.crl = Some(KeyData::Mem(mem.to_vec()));
        self
    }

    /// Set the parameters of an Diffie-Hellman Ephemeral (DHE) key exchange.
    ///
    /// # See also
    ///
    /// [`Config::set_dheparams`](struct.Config.html#method.set_dheparams)
    pub fn dheparams(&'_ mut self, dheparams: &str) -> &'_ mut Self {
        self.dheparams = Some(dheparams.to_owned());
        self
    }

    /// Set the curves of an Elliptic Curve Diffie-Hellman Ephemeral (ECDHE) key exchange.
    ///
    /// # See also
    ///
    /// [`Config::set_ecdhecurves`](struct.Config.html#method.set_ecdhecurves)
    pub fn ecdhecurves(&'_ mut self, ecdhecurves: &str) -> &'_ mut Self {
        self.ecdhecurves = Some(ecdhecurves.to_owned());
        self
    }

    /// Add additional files of a public and private key pair and OCSP staple.
    ///
    /// # See also
    ///
    /// [`Config::add_keypair_file`](struct.Config.html#method.add_keypair_ocsp_file),
    /// [`Config::set_keypair_file`](struct.Config.html#method.set_keypair_ocsp_file)
    pub fn keypair_file<P: AsRef<Path>>(
        &'_ mut self,
        cert: P,
        key: P,
        ocsp_staple: Option<P>,
    ) -> &'_ mut Self {
        let certdata = cert.as_ref().to_owned();
        let keydata = key.as_ref().to_owned();
        let ocspdata = match ocsp_staple {
            Some(path) => Some(path.as_ref().to_owned()),
            None => None,
        };
        self.keypairs
            .push(KeyData::KeyPairFiles(certdata, keydata, ocspdata));
        self
    }

    /// Add an additional public and private key pair and OCSP staple from memory.
    ///
    /// # See also
    ///
    /// [`Config::set_keypair_mem`](struct.Config.html#method.add_keypair_ocsp_mem),
    /// [`Config::set_keypair_mem`](struct.Config.html#method.set_keypair_ocsp_mem)
    pub fn keypair_mem(
        &'_ mut self,
        cert: &[u8],
        key: &[u8],
        ocsp_staple: Option<&[u8]>,
    ) -> &'_ mut Self {
        let certdata = cert.to_vec();
        let keydata = key.to_vec();
        let ocspdata = match ocsp_staple {
            Some(mem) => Some(mem.to_vec()),
            None => None,
        };
        self.keypairs
            .push(KeyData::KeyPairMem(certdata, keydata, ocspdata));
        self
    }

    /// Disable certificate verification.
    ///
    /// # See also
    ///
    /// [`Config::insecure_noverifycert`](struct.Config.html#method.insecure_noverifycert)
    pub fn noverifycert(&'_ mut self) -> &'_ mut Self {
        self.noverifycert = true;
        self
    }

    /// Disable server name verification.
    ///
    /// # See also
    ///
    /// [`Config::insecure_noverifyname`](struct.Config.html#method.insecure_noverifyname)
    pub fn noverifyname(&'_ mut self) -> &'_ mut Self {
        self.noverifyname = true;
        self
    }

    /// Disable certificate validity checking.
    ///
    /// # See also
    ///
    /// [`Config::insecure_noverifytime`](struct.Config.html#method.insecure_noverifytime)
    pub fn noverifytime(&'_ mut self) -> &'_ mut Self {
        self.noverifytime = true;
        self
    }

    /// Set which versions of the TLS protocol may be used.
    ///
    /// # See also
    ///
    /// [`Config::set_protocols`](struct.Config.html#method.set_protocols)
    pub fn protocols(&'_ mut self, protocols: u32) -> &'_ mut Self {
        self.protocols = Some(protocols);
        self
    }

    /// Set a file descriptor to manage data for TLS sessions.
    ///
    /// # See also
    ///
    /// [`Config::set_session_fd`](struct.Config.html#method.set_session_fd)
    pub fn session_fd(&'_ mut self, fd: RawFd) -> &'_ mut Self {
        self.session_fd = Some(fd);
        self
    }

    /// Set the session identifier for TLS sessions.
    ///
    /// # See also
    ///
    /// [`Config::set_session_id`](struct.Config.html#method.set_session_id)
    pub fn session_id(&'_ mut self, id: &[u8]) -> &'_ mut Self {
        self.session_id = Some(id.to_vec());
        self
    }

    /// Set the lifetime for TLS sessions.
    ///
    /// # See also
    ///
    /// [`Config::set_session_lifetime`](struct.Config.html#method.set_session_lifetime)
    pub fn session_lifetime(&'_ mut self, lifetime: usize) -> &'_ mut Self {
        self.session_lifetime = Some(lifetime);
        self
    }

    /// # See also
    ///
    /// [`Config::add_ticket_key`](struct.Config.html#method.add_ticket_key)
    pub fn ticket_key(&'_ mut self, keyrev: u32, key: &[u8]) -> &'_ mut Self {
        self.ticket_key.insert(keyrev, key.to_vec());
        self
    }

    /// Enable all certificate verification.
    ///
    /// # See also
    ///
    /// [`Config::verify`](struct.Config.html#method.verify)
    pub fn verify(&'_ mut self) -> &'_ mut Self {
        self.verify = true;
        self
    }

    /// Enable client certificate verification.
    ///
    /// # See also
    ///
    /// [`Config::verify_client`](struct.Config.html#method.verify_client)
    pub fn verify_client(&'_ mut self) -> &'_ mut Self {
        self.verify_client = true;
        self
    }

    /// Enable optional client certificate verification.
    ///
    /// # See also
    ///
    /// [`Config::verify_client_optional`](struct.Config.html#method.verify_client_optional)
    pub fn verify_client_optional(&'_ mut self) -> &'_ mut Self {
        self.verify_client_optional = true;
        self
    }

    /// Set the certificate verification depth.
    ///
    /// # See also
    ///
    /// [`Config::verify_depth`](struct.Config.html#method.verify_depth)
    pub fn verify_depth(&'_ mut self, depth: usize) -> &'_ mut Self {
        self.verify_depth = Some(depth);
        self
    }
}
