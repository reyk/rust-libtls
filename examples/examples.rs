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

#![allow(dead_code)]

use std::env;

pub struct Examples {
    pub server_key: String,
    pub server_cert: String,
    pub ca_cert: String,
    pub server_addr: String,
    pub www_example: String,
}

fn testdata() -> String {
    env::var("CARGO_MANIFEST_DIR").unwrap() + "/../libtls/tests/"
}

impl Examples {
    pub fn new() -> Self {
        Self {
            server_cert: testdata() + "eccert.crt",
            server_key: testdata() + "eccert.key",
            ca_cert: testdata() + "eccert.crt",
            server_addr: "[::1]:7000".to_string(),
            www_example: "www.example.com".to_string(),
        }
    }
}
