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

use futures::join;
use std::{io, net::SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_libtls::prelude::*;

/// Echo server
async fn echo_server(addr: &str, cert: &str, key: &str) -> io::Result<()> {
    let config = Builder::new().keypair_file(cert, key, None).build()?;

    let addr: SocketAddr = addr.parse().unwrap();
    let mut listener = TcpListener::bind(&addr).await?;

    loop {
        let mut tls = accept(&mut listener, &config, None).await?;
        tokio::spawn(async move {
            loop {
                let mut buf = vec![0u8; 1024];
                let len = match tls.read(&mut buf).await {
                    Ok(len) => len,
                    _ => break,
                };
                if tls.write_all(&buf[..len]).await.is_err() {
                    break;
                }
            }
        });
    }
}

/// Echo client
async fn echo_client(addr: &str, ca: &str, message: &str) -> io::Result<()> {
    let data = message.as_bytes();

    // This example doesn't have a name in the certificate.
    let config = Builder::new().ca_file(ca).noverifyname().build()?;

    let mut tls = connect(addr, &config, None).await?;

    eprintln!("client: {}", message);
    tls.write_all(data).await?;

    let mut buf = vec![0u8; 1024];
    let len = tls.read(&mut buf).await?;
    eprintln!("server: {}", message);

    assert_eq!(&buf[..len], data);

    // Terminate the process to stop the server of this example
    std::process::exit(0);
}

#[tokio::main]
async fn main() {
    let examples = examples::Examples::new();
    let server = echo_server(
        &examples.server_addr,
        &examples.server_cert,
        &examples.server_key,
    );
    let client = echo_client(&examples.server_addr, &examples.ca_cert, "Hello Echo!");

    let (server, client) = join!(server, client);
    client.unwrap();
    server.unwrap();
}
