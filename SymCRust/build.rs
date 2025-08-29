fn main() {
    #[cfg(all(feature = "std", not(feature = "benchmarking")))]
    {
        use std::env;

        // When building for benchmarking, we use pure Rust and mock out any external dependencies, so we
        // don't need to link libsymcrypt in that case
        let lib_path = env::var("SYMCRYPT_LIB_PATH")
            .unwrap_or_else(|_| panic!("SYMCRYPT_LIB_PATH environment variable not set. See README.md."));
        println!("cargo::rustc-link-search=native={}", lib_path);
        println!("cargo::rustc-link-lib=static=symcrypt_generic");
        println!("cargo::rustc-link-lib=static=symcrypt_common");
    }
}