// build.rs - locate and link the SymCrypt C library
// Strategy:
// 1. Try pkg-config for `symcrypt` (will work if the C build installed a .pc file)
// 2. If pkg-config fails, look for the repository `build` folder next to the workspace root
//    and use its output (lib/symcrypt.lib or libsymcrypt.a) as a fallback.

use std::env;
use std::path::PathBuf;

fn main() {
    // Prefer pkg-config if available
    if pkg_config::probe_library("symcrypt").is_ok() {
        println!("cargo::warning=Found SymCrypt via pkg-config");
        return;
    }

    // Fall back: assume parent directory (workspace root) built SymCrypt with CMake
    // Common out path in this repo is ../build/lib or ../bin depending on configuration.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or(manifest_dir.clone());

    // HACK: Need to integrate this better with the CMake build script
    let fallback_lib_dirs = [repo_root.join("build/cmake/Windows_AMD64_Debug/exe")];

    for dir in &fallback_lib_dirs {
        if dir.exists() {
            println!("cargo:rustc-link-search=native={}", dir.display());
            println!("cargo:rustc-link-lib=dylib=symcrypt");

            println!("cargo::warning=Found SymCrypt in {}", dir.display());
            
            // Copy DLL to the target output directory so tests and executables can find it.
            // Note: build scripts are not compiled with `cfg(test)`, so trying to detect
            // `test` here (e.g. with `cfg!(test)`) doesn't work. Copying unconditionally is
            // harmless and ensures the DLL is available for `cargo test` and regular runs.
            {
                let dll_name = if cfg!(windows) {
                    "symcrypt.dll"
                } else if cfg!(target_os = "macos") {
                    "libsymcrypt.dylib"
                } else {
                    "libsymcrypt.so"
                };
                
                let dll_path = dir.join(dll_name);
                if dll_path.exists() {
                    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
                    let target_dir = out_dir.parent().unwrap().parent().unwrap().parent().unwrap();
                    let dest_path = target_dir.join(dll_name);
                    
                    if let Err(e) = std::fs::copy(&dll_path, &dest_path) {
                        println!("cargo:warning=Failed to copy {} to test directory: {}", dll_name, e);
                    }
                    else {
                        println!("cargo:warning=Successfully copied {} to {}", dll_name, dest_path.display());
                    }
                }
                else {
                    println!("cargo:warning=Could not find {} in {}", dll_name, dir.display());
                }
            }
            return;
        }
    }

    // As a last resort, emit helpful error via build script print (still allows build to continue
    // but linking will fail later). This message will appear during cargo build.
    println!("cargo:warning=Could not find SymCrypt via pkg-config or repo build directories.\nPlease build SymCrypt C library with CMake and either install a pkg-config file or place the library under ../build or ../bin relative to SymCRust/Cargo.toml.");
}
