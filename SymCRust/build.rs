fn main() {
    // `not(verify)`: the Charon/Aeneas extraction build (`--features verify`) compiles
    // the crate with a public toolchain and never links libsymcrypt, so skip the
    // SYMCRYPT_LIB_PATH requirement and link directives there. This is the only
    // deviation from `feature/verifiedcrypto`'s build.rs, and it is verification-required.
    #[cfg(all(feature = "std", not(any(feature = "benchmarking", feature = "verify"))))]
    {
        use std::env;

        // When building for benchmarking, we use pure Rust and mock out any external dependencies, so we
        // don't need to link libsymcrypt in that case
        let lib_path = env::var("SYMCRYPT_LIB_PATH").unwrap_or_else(|_| {
            panic!("SYMCRYPT_LIB_PATH environment variable not set. See README.md.")
        });
        println!("cargo::rustc-link-search=native={}", lib_path);
        println!("cargo::rustc-link-lib=static=symcryptunittest_env_lib");
        println!("cargo::rustc-link-lib=static=symcrypt_common");
    }
}
