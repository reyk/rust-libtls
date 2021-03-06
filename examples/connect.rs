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

mod examples;

use libtls::{config, error};
use std::io::{Read, Write};

fn sync_https_connect(servername: &str) -> error::Result<()> {
    let addr = &(servername.to_owned() + ":443");

    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: {}\r\n\
         Connection: close\r\n\r\n",
        servername
    );

    let mut tls = config::Builder::new().client()?;

    tls.connect(addr, None)?;
    tls.write_all(request.as_bytes())?;

    let mut buf = vec![0u8; 1024];
    tls.read_exact(&mut buf)?;

    let ok = b"HTTP/1.1 200 OK\r\n";
    assert_eq!(&buf[..ok.len()], ok);

    Ok(())
}

fn main() {
    let examples = examples::Examples::new();
    sync_https_connect(&examples.www_example).unwrap();
}
