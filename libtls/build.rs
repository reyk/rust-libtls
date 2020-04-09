fn main() {
    if libtls_sys::TLS_API >= 20200120 {
        println!("cargo:rustc-cfg=libressl_3_1_0");
    }
}
