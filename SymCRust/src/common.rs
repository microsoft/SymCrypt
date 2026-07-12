//
// common.rs   Common definitions that set up SymCRust environment
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

// The SYMCRYPT_ERROR C enum, mapped to Rust
//
// FIXME: for now, this is manually kept in sync between Rust and C -- can we automate?

#![allow(dead_code)]

use alloc::boxed::Box;
use core::alloc::Layout;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{__m128i, _mm_loadu_si128, _mm_storeu_si128};

#[cfg(target_arch = "x86")]
use core::arch::x86::{__m128i, _mm_loadu_si128, _mm_storeu_si128};

use crate::symcryptcommon::{
    g_SymCryptCpuFeaturesNotPresent, g_SymCryptFipsSelftestsPerformed, SymCryptCallbackRandom,
    SymCryptCpuFeaturesNeverPresent, SymCryptInit, SymCryptWipe,
};

#[allow(clippy::enum_variant_names)]
#[derive(PartialEq, Debug, Clone)]
#[repr(C)]
pub enum Error {
    NoError = 0,
    Unused = 0x8000, // Start our error codes here so they're easier to distinguish
    WrongKeySize,
    WrongBlockSize,
    WrongDataSize,
    WrongNonceSize,
    WrongTagSize,
    WrongIterationCount,
    AuthenticationFailure,
    ExternalFailure,
    FipsFailure,
    HardwareFailure,
    NotImplemented,
    InvalidBlob,
    BufferTooSmall,
    InvalidArgument,
    MemoryAllocationFailure,
    SignatureVerificationFailure,
    IncompatibleFormat,
    ValueTooLarge,
    SessionReplayFailure,
    HbsNoOtsKeysLeft,
    HbsPublicRootMismatch,
}

#[derive(PartialEq, Debug, Clone)]
#[repr(C)]
pub enum SelftestAlgorithm {
    NONE = 0x0,
    STARTUP = 0x1,
    DSA = 0x2,
    ECDSA = 0x4,
    RSA = 0x8,
    DH = 0x10,
    ECDH = 0x20,
    MLKEM = 0x40,
    XMSS = 0x80,
    LMS = 0x100,
    MLDSA = 0x200,
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64", feature = "verify"))]
pub const SYMCRYPT_CPU_FEATURE_SSE2: u32 = 0x1;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub const SYMCRYPT_CPU_FEATURE_PCLMULQDQ: u32 = 0x8;
#[cfg(any(target_arch = "aarch64", feature = "verify"))]
pub const SYMCRYPT_CPU_FEATURE_NEON: u32 = 0x1;

// Allows printing errors, which is a prerequisite for using ERROR as an argument to
// core::result::Result.
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:?} ({:x})", self, self.clone() as u16)
    }
}

// Allows using errors within core::result::Result.
impl core::error::Error for Error {}

#[cfg(not(feature = "verify"))]
pub(crate) fn init() {
    static INITIALIZED: AtomicBool = AtomicBool::new(false);

    if INITIALIZED.load(Ordering::Relaxed) {
        return;
    }

    unsafe {
        SymCryptInit();
    }

    INITIALIZED.store(true, Ordering::Relaxed);
}

#[cfg_attr(feature = "verify", verify::opaque)]
pub fn cpu_features_present(feature_mask: u32) -> bool {
    unsafe {
        ((SymCryptCpuFeaturesNeverPresent() & feature_mask) == 0)
            && ((g_SymCryptCpuFeaturesNotPresent & feature_mask) == 0)
    }
}

#[cfg(not(feature = "verify"))]
pub fn run_selftest_once(selftest_fn: unsafe extern "C" fn(), selftest_flag: u32) {
    unsafe {
        if (g_SymCryptFipsSelftestsPerformed.load(Ordering::Relaxed) & selftest_flag) == 0 {
            selftest_fn();
            g_SymCryptFipsSelftestsPerformed.fetch_or(selftest_flag, Ordering::Relaxed);
        }
    }
}

#[cfg_attr(feature = "verify", verify::opaque)]
pub(crate) fn random(dst: &mut [u8]) -> Error {
    unsafe { SymCryptCallbackRandom(dst.as_mut_ptr(), dst.len()) }
}

#[cfg_attr(feature = "verify", verify::exclude)]
pub fn wipe(pb_data: *mut u8, cb_data: usize) {
    unsafe { SymCryptWipe(pb_data, cb_data) }
}

#[cfg_attr(feature = "verify", verify::opaque)]
pub fn wipe_slice<T>(pb_dst: &mut [T]) {
    wipe(pb_dst.as_mut_ptr().cast(), core::mem::size_of_val(pb_dst));
}

/// In cryptography, we often do in-place operations for performance reasons, but we also want to
/// support scenarios with separate source and destination buffers. This struct allows us to support
/// both scenarios in a Rust-friendly way, without requiring separate APIs for in-place vs.
/// out-of-place operations. It can be thought of as a smart pointer that wraps either one or two
/// buffers, which can be constructed from slices or raw pointers (for FFI use).
///
/// For `InPlace`, the same buffer is used for both source and destination.
/// For `Disjoint`, separate source and destination buffers are used.
///
/// Note: the struct does not own the buffers, so it is the caller's responsibility to wipe any
/// sensitive data after use.
#[cfg_attr(feature = "verify", verify::opaque)]
pub struct InPlaceOrDisjointBuffer<'a, T> {
    src: *const T,
    dst: *mut T,
    len: usize,
    _phantom: PhantomData<&'a mut [T]>,
}

impl<'a, T> InPlaceOrDisjointBuffer<'a, T> {
    /// Create an `InPlaceOrDisjointBuffer` from a single mutable slice for in-place operations.
    #[cfg_attr(feature = "verify", verify::opaque)]
    pub fn new_in_place(buffer: &'a mut [T]) -> Self {
        let ptr = buffer.as_mut_ptr();
        Self {
            src: ptr as *const T,
            dst: ptr,
            len: buffer.len(),
            _phantom: PhantomData,
        }
    }

    /// Create an `InPlaceOrDisjointBuffer` from two separate slices for disjoint operations.
    #[cfg_attr(feature = "verify", verify::opaque)]
    pub fn new_disjoint<const N: usize>(src: &'a [T; N], dst: &'a mut [T; N]) -> Self {
        Self {
            src: src.as_ptr(),
            dst: dst.as_mut_ptr(),
            len: N,
            _phantom: PhantomData,
        }
    }

    /// Create an `InPlaceOrDisjointBuffer` from two separate slices for disjoint operations.
    /// This function is for use when the size of the slices is not known at compile time. For
    /// fixed-size arrays, prefer `new_disjoint`.
    #[cfg_attr(feature = "verify", verify::opaque)]
    pub fn new_disjoint_from_slices(src: &'a [T], dst: &'a mut [T]) -> Self {
        assert_eq!(src.len(), dst.len());
        Self {
            src: src.as_ptr(),
            dst: dst.as_mut_ptr(),
            len: src.len(),
            _phantom: PhantomData,
        }
    }

    /// Create an `InPlaceOrDisjointBuffer` from potentially overlapping raw pointers
    ///
    /// # Safety
    /// - `src` must be valid for accesses of `len` elements
    /// - `dst` must be valid for accesses of `len` elements
    /// - `src` and `dst` must be either equal or completely disjoint
    /// - When `src` and `dst` are disjoint, they must have the same length
    /// - Both `src` and `dst` must be valid for the lifetime of the returned buffer
    #[cfg_attr(feature = "verify", verify::exclude)]
    pub unsafe fn from_raw_parts(src: *const T, dst: *mut T, len: usize) -> Self {
        Self {
            src,
            dst,
            len,
            _phantom: PhantomData,
        }
    }

    #[cfg_attr(feature = "verify", verify::opaque)]
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Load a 128-bit value from source at the given byte offset using _mm_loadu_si128.
    /// There are no alignment restrictions.
    ///
    /// # Arguments
    /// - `offset`: offset into the source buffer, in elements of T
    ///
    /// # Safety
    /// Caller must ensure offset < self.len() and offset * sizeof(T) + 16 <= self.len * sizeof(T)
    #[cfg_attr(feature = "verify", verify::opaque)]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "sse2")]
    #[inline]
    pub unsafe fn loadu_si128_src(&self, offset: usize) -> __m128i {
        debug_assert!(offset * core::mem::size_of::<T>() + 16 <= self.len() * core::mem::size_of::<T>());
        _mm_loadu_si128(self.src.add(offset) as *const __m128i)
    }

    /// Load a 128-bit value from **destination** buffer at the given offset using
    /// _mm_loadu_si128. There are no alignment restrictions.
    ///
    /// # Arguments
    /// - `offset`: offset into the destination buffer, in elements of T
    ///
    /// Normally in cryptography we follow the read-once write-once rule, meaning we read each byte
    /// of the source exactly once and write each byte of the destination exactly once. However,
    /// some algorithm implementations (specifically, AES-GCM) require reading back from the
    /// destination buffer after writing to it; to do otherwise would have a significant
    /// performance impact.
    ///
    /// # Safety
    /// Caller must ensure offset < self.len() and offset * sizeof(T) + 16 <= self.len * sizeof(T)
    #[cfg_attr(feature = "verify", verify::opaque)]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "sse2")]
    #[inline]
    pub unsafe fn loadu_si128_dst(&self, offset: usize) -> __m128i {
        debug_assert!(offset * core::mem::size_of::<T>() + 16 <= self.len() * core::mem::size_of::<T>());
        _mm_loadu_si128(self.dst.add(offset) as *const __m128i)
    }

    /// Store a 128-bit value to destination at the given byte offset using _mm_storeu_si128.
    /// There are no alignment restrictions.
    ///
    /// # Arguments
    /// - `offset`: offset into the destination buffer, in elements of T
    /// - `value`: value to store
    ///
    /// # Safety
    /// Caller must ensure offset < self.len() and offset * sizeof(T) + 16 <= self.len * sizeof(T)
    #[cfg_attr(feature = "verify", verify::opaque)]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "sse2")]
    #[inline]
    pub unsafe fn storeu_si128(&mut self, offset: usize, value: __m128i) {
        debug_assert!(offset * core::mem::size_of::<T>() + 16 <= self.len() * core::mem::size_of::<T>());
        _mm_storeu_si128(self.dst.add(offset) as *mut __m128i, value)
    }

    /// Get a reference to the source buffer as a slice.
    #[cfg_attr(feature = "verify", verify::opaque)]
    pub fn src(&self) -> &[T] {
        unsafe { core::slice::from_raw_parts(self.src, self.len) }
    }

    /// Get a mutable reference to the destination buffer as a mutable slice.
    #[cfg_attr(feature = "verify", verify::opaque)]
    pub fn dst(&mut self) -> &mut [T] {
        unsafe { core::slice::from_raw_parts_mut(self.dst, self.len) }
    }
}

/// Trait for types that can be default-initialized directly on the heap.
pub unsafe trait BoxDefault {
    /// Implementors receive a raw pointer to heap memory that has been zero-initialized
    /// via `alloc_zeroed`. The `box_default` method must write any fields whose default
    /// value is not all-zeros. Intended to be used in conjunction with `try_new_box_default`.
    ///
    /// Any implementation of box_default must not panic.
    unsafe fn box_default(ptr: *mut Self);
}

// Helper function to allocate a zero-initialized block of memory on the heap.
// Could potentially be replaced by Box::<T>::try_new_zeroed once stabilized.
#[cfg_attr(feature = "verify", verify::exclude)]
unsafe fn try_alloc_zeroed<T>() -> Result<*mut T, Error> {
    let layout = Layout::new::<T>();
    let ptr = alloc::alloc::alloc_zeroed(layout).cast::<T>();
    if ptr.is_null() {
        return Err(Error::MemoryAllocationFailure);
    }
    Ok(ptr)
}

/// Allocates a `Box<T>` on the heap, initialized as all zeroes.
///
/// Primarily useful when only a zero-allocated buffer is needed
/// without wanting to implement BoxDefault (e.g. zero-initializing
/// an array on the heap)
///
/// T must be valid when zero-initialized.
#[cfg_attr(feature = "verify", verify::opaque)]
pub fn try_new_box_zeroed<T>() -> Result<Box<T>, Error> {
    unsafe {
        let ptr = try_alloc_zeroed::<T>()?;
        Ok(Box::from_raw(ptr))
    }
}

/// Allocates a `Box<T>` on the heap, initialized via `T::box_default`.
///
/// Relies on the type-specific BoxDefault implementation to initialize any
/// non-zero fields. This avoids first constructing values on the stack,
/// which is especially important when in environments like the kernel
/// where stack space is limited.
#[cfg_attr(feature = "verify", verify::opaque)]
pub fn try_new_box_default<T: BoxDefault>() -> Result<Box<T>, Error> {
    unsafe {
        let ptr = try_alloc_zeroed::<T>()?;
        T::box_default(ptr);
        Ok(Box::from_raw(ptr))
    }
}

/// Constant-time memory comparison.
///
/// Compares two byte slices in constant time, ensuring that:
/// - All bytes from both slices are read
/// - The comparison time does not depend on where the first difference occurs
/// - Returns true if all bytes match, false otherwise

/// Wrapper function for static-length arrays, with length equality enforced at compile time.
pub fn const_time_arrays_equal<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    unsafe {
        const_time_slices_equal_impl(a.as_slice(), b.as_slice())
    }
}

/// Wrapper function for runtime-sized slices, with length equality checked at runtime, generating a panic if lengths differ.
pub fn const_time_slices_equal(a: &[u8], b: &[u8]) -> bool {
    assert_eq!(a.len(), b.len());
    unsafe {
        const_time_slices_equal_impl(a, b)
    }
}

// This function is unsafe because it will trigger UB in release mode if b.len() < a.len().
#[inline(never)] // Prevent inlining to help ensure constant-time behavior
#[cfg_attr(feature = "verify", verify::opaque)]
unsafe fn const_time_slices_equal_impl(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());

    let len = a.len();
    let mut diff: u8 = 0;

    // TODO: consider wider reads for performance (may require explicit alignment)

    // Accumulate all differences without short-circuiting
    for i in 0..len {
        let ai = unsafe { core::ptr::read_volatile(a.as_ptr().add(i)) };
        let bi = unsafe { core::ptr::read_volatile(b.as_ptr().add(i)) };
        diff |= ai ^ bi;
    }

    // Return true if no differences were found
    diff == 0
}

/// Constant-time memory copy based on a copy size.
///
/// Copies bytes from source `a` to destination `b` in constant time,
/// based on the specified `copy_size`. The function ensures that:
/// - All bytes from both source and destination are read and all bytes in the destination slice are written
/// - The copy operation time does not depend on the `copy_size`
/// - Only the first `copy_size` bytes are copied from `a` to `b`
/// - If `copy_size` is greater than the slice length, all source bytes are copied, but this will panic in debug builds

/// Wrapper function for static-length arrays, with length equality enforced at compile time.
pub fn const_time_array_copy<const N: usize>(a: &[u8; N], b: &mut [u8; N], copy_size: u32) {
    const {
        assert!(N <= u32::MAX as usize, "Array length exceeds u32::MAX");
    }
    unsafe {
        const_time_slice_copy_impl(a.as_slice(), b.as_mut_slice(), copy_size);
    }
}

/// Wrapper function for runtime-sized slices, with length equality checked at runtime, generating a panic if lengths differ.
pub fn const_time_slice_copy(a: &[u8], b: &mut [u8], copy_size: u32) {
    assert_eq!(a.len(), b.len());
    unsafe {
        const_time_slice_copy_impl(a, b, copy_size);
    }
}

// This function is unsafe because it will trigger UB in release mode if b.len() < a.len().
#[inline(never)] // Prevent inlining to help ensure constant-time behavior
#[cfg_attr(feature = "verify", verify::opaque)]
unsafe fn const_time_slice_copy_impl(a: &[u8], b: &mut [u8], copy_size: u32) {
    debug_assert_eq!(a.len(), b.len());
    debug_assert!(
        u32::try_from(a.len()).is_ok(),
        "Slices length exceeds u32::MAX"
    );
    debug_assert!(
        a.len() >= copy_size as usize,
        "Slices are too small for copy"
    );

    let len = a.len();

    // TODO: consider wider reads/writes for performance (may require explicit alignment)

    for i in 0..len {
        let ai = unsafe { core::ptr::read_volatile(a.as_ptr().add(i)) };
        let mut bi = unsafe { core::ptr::read_volatile(b.as_ptr().add(i)) };
        let mask = (((i as u32).wrapping_sub(copy_size) as i32) >> 31) as u8;
        bi ^= (ai ^ bi) & mask;
        unsafe { core::ptr::write_volatile(b.as_mut_ptr().add(i), bi) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_place_buffer_basic_operations() {
        let mut data = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mut buffer = InPlaceOrDisjointBuffer::new_in_place(&mut data);

        assert_eq!(buffer.len(), 16);

        // Test that we can access via safe borrow-checked methods
        {
            let src = buffer.src();
            assert_eq!(src[0], 1);
            assert_eq!(src[15], 16);
        }

        {
            let dst = buffer.dst();
            dst[0] = 99;
            dst[15] = 88;
        }

        // Verify modifications
        assert_eq!(data[0], 99);
        assert_eq!(data[15], 88);
    }

    #[test]
    fn test_disjoint_buffer_basic_operations() {
        let src = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mut dst = [0u8; 16];

        let mut buffer = InPlaceOrDisjointBuffer::new_disjoint(&src, &mut dst);

        assert_eq!(buffer.len(), 16);

        // Test that source and destination are separate using safe API
        {
            let src_slice = buffer.src();
            assert_eq!(src_slice[0], 1);
            assert_eq!(src_slice[15], 16);
        }

        {
            let dst_slice = buffer.dst();
            dst_slice[0] = 99;
            dst_slice[15] = 88;
        }

        // Source should be unchanged
        assert_eq!(src[0], 1);
        assert_eq!(src[15], 16);

        // Destination should be modified
        assert_eq!(dst[0], 99);
        assert_eq!(dst[15], 88);
    }

    #[test]
    fn test_disjoint_buffer_from_slices() {
        let src = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut dst = vec![0u8; 8];

        let mut buffer = InPlaceOrDisjointBuffer::new_disjoint_from_slices(&src, &mut dst);

        assert_eq!(buffer.len(), 8);

        let src_vec = buffer.src().to_vec();
        buffer.dst().copy_from_slice(&src_vec);

        assert_eq!(&dst[..], &src[..]);
    }

    #[test]
    fn test_buffer_from_raw_parts_in_place() {
        let mut data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let ptr = data.as_mut_ptr();

        unsafe {
            // Create an in-place buffer from raw parts where src == dst
            let buffer = InPlaceOrDisjointBuffer::from_raw_parts(ptr as *const u8, ptr, 8);

            assert_eq!(buffer.len(), 8);

            let src = buffer.src();
            assert_eq!(src[0], 1);
        }
    }

    #[test]
    fn test_buffer_from_raw_parts_disjoint() {
        let src = [1u8, 2, 3, 4];
        let mut dst = [0u8; 4];

        unsafe {
            let mut buffer =
                InPlaceOrDisjointBuffer::from_raw_parts(src.as_ptr(), dst.as_mut_ptr(), 4);

            assert_eq!(buffer.len(), 4);

            let src_vec = buffer.src().to_vec();
            assert_eq!(src_vec, src);

            buffer.dst()[0..4].copy_from_slice(&src_vec);
            assert_eq!(dst, [1, 2, 3, 4]);
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    #[test]
    fn test_simd_operations_in_place() {
        let mut data = [0u8; 32];
        for i in 0..32 {
            data[i] = i as u8;
        }

        let mut buffer = InPlaceOrDisjointBuffer::new_in_place(&mut data);

        unsafe {
            // Load from source at offset 0
            let val = buffer.loadu_si128_src(0);

            // Store to destination at offset 16
            buffer.storeu_si128(16, val);
        }

        // First 16 bytes should be copied to the second 16 bytes
        assert_eq!(&data[0..16], &data[16..32]);
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    #[test]
    fn test_simd_operations_disjoint() {
        let mut src = [0u8; 16];
        for i in 0..16 {
            src[i] = i as u8;
        }
        let mut dst = [0u8; 16];

        let mut buffer = InPlaceOrDisjointBuffer::new_disjoint(&src, &mut dst);

        unsafe {
            let val = buffer.loadu_si128_src(0);
            buffer.storeu_si128(0, val);
        }

        // Data should be copied from src to dst
        assert_eq!(&src[..], &dst[..]);
    }

    #[test]
    #[should_panic]
    fn test_disjoint_from_slices_length_mismatch() {
        let src = vec![1u8, 2, 3, 4];
        let mut dst = vec![0u8; 8]; // Different length

        let _ = InPlaceOrDisjointBuffer::new_disjoint_from_slices(&src, &mut dst);
    }

    #[test]
    fn test_wipe_functions() {
        // Test wipe function
        let mut data = [0xFFu8; 32];
        wipe(data.as_mut_ptr(), data.len());
        assert_eq!(data, [0u8; 32]);

        // Test wipe_slice
        let mut data = [0xAAu8; 16];
        wipe_slice(&mut data);
        assert_eq!(data, [0u8; 16]);
    }

    #[test]
    fn test_const_time_arrays_equal() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];

        assert!(const_time_arrays_equal(&a, &b));
        assert!(!const_time_arrays_equal(&a, &c));
    }

    #[test]
    fn test_const_time_slices_equal() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];

        assert!(const_time_slices_equal(&a, &b));
        assert!(!const_time_slices_equal(&a, &c));
    }

    #[test]
    #[should_panic]
    fn test_const_time_slices_equal_length_mismatch() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3];

        let _ = const_time_slices_equal(&a, &b);
    }

    #[test]
    fn test_const_time_array_copy() {
        let src = [1u8, 2, 3, 4, 5];
        let mut dst = [0u8; 5];

        // Copy first 3 bytes
        const_time_array_copy(&src, &mut dst, 3);
        assert_eq!(dst, [1, 2, 3, 0, 0]);

        // Copy all bytes
        let mut dst = [0u8; 5];
        const_time_array_copy(&src, &mut dst, 5);
        assert_eq!(dst, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_const_time_slice_copy() {
        let src = [1u8, 2, 3, 4, 5];
        let mut dst = [0u8; 5];

        // Copy first 2 bytes
        const_time_slice_copy(&src, &mut dst, 2);
        assert_eq!(dst, [1, 2, 0, 0, 0]);
    }
}
