///
/// kernel_stubs.rs
///
/// Stub implementations for symbols required by Rust's compiler_builtins when
/// using build-std for Windows kernel mode.
///
/// When building Rust for Windows kernel, we use build-std to recompile the
/// standard library without C++ exception handling (SEH). The compiler_builtins
/// crate references these symbols even though our Rust code doesn't use
/// floating-point operations.
///

// _fltused is normally provided by CRT, which doesn't exist in kernel mode.
#[used]
#[no_mangle]
pub static _fltused: i32 = 0;

// fma/fmaf are referenced by compiler_builtins but never called by our code.
#[no_mangle]
pub extern "C" fn fma(_x: f64, _y: f64, _z: f64) -> f64 {
    panic!("fma is not supported in kernel mode");
}

#[no_mangle]
pub extern "C" fn fmaf(_x: f32, _y: f32, _z: f32) -> f32 {
    panic!("fmaf is not supported in kernel mode");
}
