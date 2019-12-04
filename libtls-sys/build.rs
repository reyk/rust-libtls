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

use std::{env, path::PathBuf};

#[cfg(target_os = "openbsd")]
fn libressl() -> Vec<String> {
    // OpenBSD doesn't install libtls.pc
    println!("cargo:rustc-link-lib=tls");
    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");
    vec!["-I/usr/include".to_owned()]
}

#[cfg(not(target_os = "openbsd"))]
fn libressl() -> Vec<String> {
    use std::{path::Path, process::Command};

    let mut libresslsrc = "libressl-portable".to_string();
    let libresslver = "v3.0.2";
    let libressltar = format!("libressl-{}.tar.gz", &libresslver[1..]);

    let curdir = env::current_dir().unwrap();
    let outdir = env::var("OUT_DIR").unwrap();

    if Path::new(&libressltar).exists() {
        Command::new("tar")
            .args(&[
                "--xform",
                &format!("s/^libressl-{}/{}/", &libresslver[1..], libresslsrc),
                "-C",
                &outdir,
                "-zxf",
                &libressltar,
            ])
            .status()
            .unwrap();
        libresslsrc = format!("{}/{}", outdir, libresslsrc);
    } else if Path::new("../.gitmodules").exists() {
        Command::new("git")
            .args(&["submodule", "update", "--init"])
            .status()
            .unwrap();
    } else {
        env::set_current_dir(&outdir).unwrap();
        Command::new("git")
            .args(&[
                "clone",
                "--single-branch",
                "-b",
                libresslver,
                "https://github.com/libressl-portable/portable.git",
                &libresslsrc,
            ])
            .status()
            .unwrap();
    }

    env::set_var("LIBRESSL_DIR", format!("{}/libressl", outdir));
    env::set_current_dir(&libresslsrc).unwrap();
    for cmd in [
        "test -s configure || ./autogen.sh",
        "./configure --prefix=$LIBRESSL_DIR --with-openssldir=$LIBRESSL_DIR --disable-shared",
        &format!("make -j{}", num_cpus::get()),
        "make install",
    ]
    .iter()
    {
        Command::new("sh").arg("-c").arg(cmd).status().unwrap();
    }
    env::set_current_dir(&curdir).unwrap();

    println!("cargo:rustc-link-search=native={}/libressl/lib", outdir);
    println!("cargo:rustc-link-lib=static=tls");
    println!("cargo:rustc-link-lib=static=ssl");
    println!("cargo:rustc-link-lib=static=crypto");
    vec![format!("-I{}/libressl/include", outdir)]
}

fn main() {
    // First try to find libtls via pkg-config -
    // "statik" is set to true but pkg_config actually only enables it
    // if the library is found outside of /usr.
    let mut pkg = pkg_config::Config::new();
    let cflags = match pkg.statik(true).atleast_version("2.9.0").probe("libtls") {
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
        Err(_) => libressl(),
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
