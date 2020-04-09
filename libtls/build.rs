fn main() {
    if libtls_sys::TLS_API >= 20_20_01_20 {
        println!("cargo:rustc-cfg=libressl_3_1_0");
    }
}
