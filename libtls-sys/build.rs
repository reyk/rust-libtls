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

extern crate bindgen;
extern crate pkg_config;

use std::env;
use std::path::PathBuf;

fn main() {
    // First try to find libtls via pkg-config
    let mut pkg = pkg_config::Config::new();
    let cflags: Vec<String> = match pkg.atleast_version("2.7.0").probe("libtls") {
        Ok(library) => {
            let mut cflags = Vec::new();
            cflags.append(
                &mut library
                    .defines
                    .iter()
                    .map(|(k, v)| format!("-D{}={}", k, v.as_ref().unwrap()))
                    .collect(),
            );
            cflags.append(
                &mut library
                    .include_paths
                    .iter()
                    .map(|p| format!("-I{}", p.display()))
                    .collect(),
            );
            cflags
        }
        Err(_) => {
            // OpenBSD doesn't install libtls.pc
            println!("cargo:rustc-link-lib=tls");
            println!("cargo:rustc-link-lib=ssl");
            println!("cargo:rustc-link-lib=crypto");
            vec!["-I/usr/include".to_owned()]
        }
    };

    // Track custom changes
    println!("cargo:rerun-if-changed=wrapper.h");

    // Generate bindings
    let bindings = bindgen::Builder::default()
        .clang_arg(cflags.join(" "))
        .header("wrapper.h")
        .generate()
        .expect("Unable to generate libtls bindings");

    let outdir = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(outdir.join("bindings.rs"))
        .expect("Couldn't write libtls bindings");
}
