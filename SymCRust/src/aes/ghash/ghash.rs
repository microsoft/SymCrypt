//
// ghash.rs   SymCrypt GHash Rust implementation
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(super) mod ghash_xmm;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::common::{cpu_features_present, SYMCRYPT_CPU_FEATURE_PCLMULQDQ};

/// GHASH arithmetic is done in the Galois field GF(2^128). In the platform-agnostic implementation,
/// an expanded key is represented as a table of 128 multiples of input key H by successive terms
/// of the field polynomial x, i.e. H, Hx, Hx^2, Hx^3, ..., Hx^127. Architecture-specific
/// implementations have different optimized representations, but never use more space than this.
pub(super) const GF128_FIELD_SIZE: usize = 128;

/// Block size for `GHash` in bytes
const GF128_BLOCK_SIZE: usize = 16;

/// Multiplication constant R for GF(2^128)
/// See D. McGrew, J. Viega, The Galois/Counter Mode of Operation (GCM)
const GF128_FIELD_R: u128 = 0xe1 << 120;

/// Multiplication constant for modular reduction (rev(0x87) << 1), excluding the high bit which
/// we XOR in manually
pub(super) const V_MULTIPLICATION_CONSTANT: i32 = 0xc2000000u32 as i32;

/// For the optimized implementations, our expanded key consists of a list of
/// N = `GHASH_OPTIMIZED_HPOWERS` powers of H. The first entry is H^N, the next H^(N-1),
/// then H^(N-2), ...
///
/// For each power we store two 128-bit values. The first is H^i (Hi) and the second contains the
/// two halves of H^i xorred with each other in the lower 64 bits (Hix).
pub(super) const GHASH_OPTIMIZED_HPOWERS: usize = 32;

/// Sentinel value for unused key table entries in debug builds
#[cfg(debug_assertions)]
const DEBUG_SENTINEL: u128 = 0xDEADBEEFDEADBEEF_DEADBEEFDEADBEEF;

/// Converts a single bit to a full-width mask, i.e. 0 -> 0, 1 -> 0xffff...
macro_rules! bit_to_mask {
    ($x:expr) => {
        ((-($x).cast_signed()).cast_unsigned())
    };
}

/// Type alias for a GF(2^128) block (128 bits / 16 bytes).
type Block = [u8; GF128_BLOCK_SIZE];

/// Expanded key for GHASH operations in GF(2^128). ABI-compatible with the equivalent C structure.
/// Contains pre-computed values for efficient GHASH computation.
/// The internal representation varies depending on whether architecture-specific
/// optimizations are available (e.g., PCLMULQDQ on x86/x86_64).
#[derive(Debug, Clone)]
#[cfg_attr(
    any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"),
    repr(align(16))
)]
#[cfg_attr(any(target_arch = "arm"), repr(align(8)))]
#[repr(C)]
pub(super) struct GHashExpandedKey([u128; GF128_FIELD_SIZE]);

// GHashExpandedKey must match SYMCRYPT_GHASH_EXPANDED_KEY.table on AMD64 / ARM64
// (the non-SYMCRYPT_GHASH_EXTRA_KEY_ALIGNMENT layout in inc/symcrypt_internal.h). The x86 C
// struct uses tableOffset + tableSpace instead and is intentionally not supported here.
const _: () = {
    assert!(core::mem::size_of::<GHashExpandedKey>() == GF128_FIELD_SIZE * 16);
    assert!(core::mem::align_of::<GHashExpandedKey>() == 16);
};

impl Default for GHashExpandedKey {
    fn default() -> Self {
        GHashExpandedKey([0u128; GF128_FIELD_SIZE])
    }
}
impl GHashExpandedKey {
    pub(super) fn new(h: &Block) -> Self {
        Self::from(h)
    }

    pub(super) fn as_slice(&self) -> &[u128; GF128_FIELD_SIZE] {
        &self.0
    }

    /// Access H^i power for optimized implementation.
    pub(super) fn h_power(&self, index: usize) -> u128 {
        let value = self.0[GHASH_OPTIMIZED_HPOWERS - index];

        #[cfg(debug_assertions)]
        {
            debug_assert_ne!(
                value, DEBUG_SENTINEL,
                "Accessing uninitialized H power at index {index}"
            );
            debug_assert_eq!(
                *self.0.last().unwrap(),
                DEBUG_SENTINEL,
                "GHASH expanded key format mismatch"
            );
        }

        value
    }

    /// Access Hx^i power for optimized implementation.
    pub(super) fn hx_power(&self, index: usize) -> u128 {
        let value = self.0[2 * GHASH_OPTIMIZED_HPOWERS - index];

        #[cfg(debug_assertions)]
        {
            debug_assert_ne!(
                value, DEBUG_SENTINEL,
                "Accessing uninitialized H power at index {index}"
            );
            debug_assert_eq!(
                *self.0.last().unwrap(),
                DEBUG_SENTINEL,
                "GHASH expanded key format mismatch"
            );
        }

        value
    }

    /// Access mutable reference to H^i power for optimized implementation.
    pub(super) fn h_power_mut(&mut self, index: usize) -> &mut u128 {
        &mut self.0[GHASH_OPTIMIZED_HPOWERS - index]
    }

    /// Access mutable reference to Hx^i power for optimized implementation.
    pub(super) fn hx_power_mut(&mut self, index: usize) -> &mut u128 {
        &mut self.0[2 * GHASH_OPTIMIZED_HPOWERS - index]
    }

    /// Expands a `GHash` key from a byte string `h`. This generic implementation works on all
    /// platforms. It computes a table of H, Hx, Hx^2, Hx^3, ..., Hx^127
    fn expand_key_generic(&mut self, h_bytes: &Block) {
        let mut h = u128::from_be_bytes(*h_bytes);
        let mut t: u128;

        for i in 0..GF128_FIELD_SIZE {
            self.0[i] = h;

            // Multiply (H1,H0) by x in the GF(2^128) field using the field encoding from SP800-38D
            t = bit_to_mask!(h & 1) & (GF128_FIELD_R);
            h >>= 1;
            h ^= t;
        }
    }

    /// Expands a `GHash` key with runtime dispatch to optimized implementations.
    /// On x86/x86_64 with PCLMULQDQ support, uses the optimized PCLMULQDQ implementation.
    /// Otherwise, falls back to the generic implementation.
    ///
    /// In debug mode, unused parts of the buffer are filled with sentinel values.
    pub(super) fn expand_key(&mut self, h_bytes: &Block) {
        #[cfg(debug_assertions)]
        {
            // Fill entire buffer with sentinel values in debug mode
            self.0.fill(DEBUG_SENTINEL);
        }

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if cpu_features_present(SYMCRYPT_CPU_FEATURE_PCLMULQDQ) {
                // SAFETY: We've verified PCLMULQDQ is available
                unsafe {
                    self.expand_key_pclmulqdq(h_bytes);
                }
                return;
            }
        }

        // Fall back to generic implementation
        self.expand_key_generic(h_bytes);
    }
}

impl From<&Block> for GHashExpandedKey {
    fn from(h: &Block) -> Self {
        let mut key = Self::default();
        key.expand_key(h);
        key
    }
}

impl Drop for GHashExpandedKey {
    fn drop(&mut self) {
        crate::common::wipe_slice(&mut self.0);
    }
}

///
/// Represents a `GHash` computation state
///
#[derive(Debug, Clone)]
pub(super) struct GHash<'a> {
    expanded_key: &'a GHashExpandedKey,
    state: u128,
}

impl<'a> GHash<'a> {
    /// Creates a new `GHash` computation state with the provided key bytes.
    pub(super) fn new(key: &'a GHashExpandedKey) -> Self {
        Self {
            expanded_key: key,
            state: 0u128,
        }
    }

    /// Appends data to the `GHash` computation state using the generic implementation.
    /// Data length must be a multiple of `GF128_BLOCK_SIZE`.
    fn append_generic(&mut self, data: &[u8]) {
        let mut r: u128;
        let mut mask: u128;

        for chunk in data.chunks_exact(GF128_BLOCK_SIZE) {
            r = 0;

            let mut t = u128::from_be_bytes(chunk.try_into().unwrap()) ^ self.state;

            for key_element in self.expanded_key.0.iter().rev() {
                mask = bit_to_mask!(t & 1);
                r ^= key_element & mask;
                t >>= 1;
            }

            self.state = r;
        }
    }

    /// Appends data to the `GHash` computation state with runtime dispatch.
    /// On x86/x86_64 with PCLMULQDQ support, uses the optimized PCLMULQDQ implementation.
    /// Otherwise, falls back to the generic implementation.
    pub(super) fn append(&mut self, data: &[u8]) {
        debug_assert!(
            data.len().is_multiple_of(GF128_BLOCK_SIZE),
            "Data length must be a multiple of GF128_BLOCK_SIZE"
        );

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if cpu_features_present(SYMCRYPT_CPU_FEATURE_PCLMULQDQ) {
                // SAFETY: We've verified PCLMULQDQ is available
                unsafe {
                    self.append_pclmulqdq(data);
                }
                return;
            }
        }

        // Fall back to generic implementation
        self.append_generic(data);
    }

    /// Returns the result of the `GHash` computation as a byte array. The state is not wiped.
    pub(super) fn result(&self) -> Block {
        self.state.to_be_bytes()
    }
}

impl Drop for GHash<'_> {
    fn drop(&mut self) {
        crate::common::wipe((&raw mut self.state).cast(), core::mem::size_of::<u128>());
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use assert_hex::assert_eq_hex;
    use ghash::universal_hash::UniversalHash;
    use rand::RngCore;

    #[test]
    fn test_ghash_expand_key() {
        crate::common::init();

        const H0: Block = [0u8; GF128_BLOCK_SIZE];
        let mut expanded_key = GHashExpandedKey::default();
        expanded_key.expand_key_generic(&H0);

        for elem in expanded_key.as_slice() {
            assert_eq!(*elem, 0u128);
        }

        const H1: Block = [1u8; GF128_BLOCK_SIZE];
        let mut expanded_key = GHashExpandedKey::default();
        expanded_key.expand_key_generic(&H1);

        const EXPECTED_KEY1: [u128; GF128_FIELD_SIZE] = [
            0x0101010101010101_0101010101010101,
            0xe180808080808080_8080808080808080,
            0x70c0404040404040_4040404040404040,
            0x3860202020202020_2020202020202020,
            0x1c30101010101010_1010101010101010,
            0x0e18080808080808_0808080808080808,
            0x070c040404040404_0404040404040404,
            0x0386020202020202_0202020202020202,
            0x01c3010101010101_0101010101010101,
            0xe1e1808080808080_8080808080808080,
            0x70f0c04040404040_4040404040404040,
            0x3878602020202020_2020202020202020,
            0x1c3c301010101010_1010101010101010,
            0x0e1e180808080808_0808080808080808,
            0x070f0c0404040404_0404040404040404,
            0x0387860202020202_0202020202020202,
            0x01c3c30101010101_0101010101010101,
            0xe1e1e18080808080_8080808080808080,
            0x70f0f0c040404040_4040404040404040,
            0x3878786020202020_2020202020202020,
            0x1c3c3c3010101010_1010101010101010,
            0x0e1e1e1808080808_0808080808080808,
            0x070f0f0c04040404_0404040404040404,
            0x0387878602020202_0202020202020202,
            0x01c3c3c301010101_0101010101010101,
            0xe1e1e1e180808080_8080808080808080,
            0x70f0f0f0c0404040_4040404040404040,
            0x3878787860202020_2020202020202020,
            0x1c3c3c3c30101010_1010101010101010,
            0x0e1e1e1e18080808_0808080808080808,
            0x070f0f0f0c040404_0404040404040404,
            0x0387878786020202_0202020202020202,
            0x01c3c3c3c3010101_0101010101010101,
            0xe1e1e1e1e1808080_8080808080808080,
            0x70f0f0f0f0c04040_4040404040404040,
            0x3878787878602020_2020202020202020,
            0x1c3c3c3c3c301010_1010101010101010,
            0x0e1e1e1e1e180808_0808080808080808,
            0x070f0f0f0f0c0404_0404040404040404,
            0x0387878787860202_0202020202020202,
            0x01c3c3c3c3c30101_0101010101010101,
            0xe1e1e1e1e1e18080_8080808080808080,
            0x70f0f0f0f0f0c040_4040404040404040,
            0x3878787878786020_2020202020202020,
            0x1c3c3c3c3c3c3010_1010101010101010,
            0x0e1e1e1e1e1e1808_0808080808080808,
            0x070f0f0f0f0f0c04_0404040404040404,
            0x0387878787878602_0202020202020202,
            0x01c3c3c3c3c3c301_0101010101010101,
            0xe1e1e1e1e1e1e180_8080808080808080,
            0x70f0f0f0f0f0f0c0_4040404040404040,
            0x3878787878787860_2020202020202020,
            0x1c3c3c3c3c3c3c30_1010101010101010,
            0x0e1e1e1e1e1e1e18_0808080808080808,
            0x070f0f0f0f0f0f0c_0404040404040404,
            0x0387878787878786_0202020202020202,
            0x01c3c3c3c3c3c3c3_0101010101010101,
            0xe1e1e1e1e1e1e1e1_8080808080808080,
            0x70f0f0f0f0f0f0f0_c040404040404040,
            0x3878787878787878_6020202020202020,
            0x1c3c3c3c3c3c3c3c_3010101010101010,
            0x0e1e1e1e1e1e1e1e_1808080808080808,
            0x070f0f0f0f0f0f0f_0c04040404040404,
            0x0387878787878787_8602020202020202,
            0x01c3c3c3c3c3c3c3_c301010101010101,
            0xe1e1e1e1e1e1e1e1_e180808080808080,
            0x70f0f0f0f0f0f0f0_f0c0404040404040,
            0x3878787878787878_7860202020202020,
            0x1c3c3c3c3c3c3c3c_3c30101010101010,
            0x0e1e1e1e1e1e1e1e_1e18080808080808,
            0x070f0f0f0f0f0f0f_0f0c040404040404,
            0x0387878787878787_8786020202020202,
            0x01c3c3c3c3c3c3c3_c3c3010101010101,
            0xe1e1e1e1e1e1e1e1_e1e1808080808080,
            0x70f0f0f0f0f0f0f0_f0f0c04040404040,
            0x3878787878787878_7878602020202020,
            0x1c3c3c3c3c3c3c3c_3c3c301010101010,
            0x0e1e1e1e1e1e1e1e_1e1e180808080808,
            0x070f0f0f0f0f0f0f_0f0f0c0404040404,
            0x0387878787878787_8787860202020202,
            0x01c3c3c3c3c3c3c3_c3c3c30101010101,
            0xe1e1e1e1e1e1e1e1_e1e1e18080808080,
            0x70f0f0f0f0f0f0f0_f0f0f0c040404040,
            0x3878787878787878_7878786020202020,
            0x1c3c3c3c3c3c3c3c_3c3c3c3010101010,
            0x0e1e1e1e1e1e1e1e_1e1e1e1808080808,
            0x070f0f0f0f0f0f0f_0f0f0f0c04040404,
            0x0387878787878787_8787878602020202,
            0x01c3c3c3c3c3c3c3_c3c3c3c301010101,
            0xe1e1e1e1e1e1e1e1_e1e1e1e180808080,
            0x70f0f0f0f0f0f0f0_f0f0f0f0c0404040,
            0x3878787878787878_7878787860202020,
            0x1c3c3c3c3c3c3c3c_3c3c3c3c30101010,
            0x0e1e1e1e1e1e1e1e_1e1e1e1e18080808,
            0x070f0f0f0f0f0f0f_0f0f0f0f0c040404,
            0x0387878787878787_8787878786020202,
            0x01c3c3c3c3c3c3c3_c3c3c3c3c3010101,
            0xe1e1e1e1e1e1e1e1_e1e1e1e1e1808080,
            0x70f0f0f0f0f0f0f0_f0f0f0f0f0c04040,
            0x3878787878787878_7878787878602020,
            0x1c3c3c3c3c3c3c3c_3c3c3c3c3c301010,
            0x0e1e1e1e1e1e1e1e_1e1e1e1e1e180808,
            0x070f0f0f0f0f0f0f_0f0f0f0f0f0c0404,
            0x0387878787878787_8787878787860202,
            0x01c3c3c3c3c3c3c3_c3c3c3c3c3c30101,
            0xe1e1e1e1e1e1e1e1_e1e1e1e1e1e18080,
            0x70f0f0f0f0f0f0f0_f0f0f0f0f0f0c040,
            0x3878787878787878_7878787878786020,
            0x1c3c3c3c3c3c3c3c_3c3c3c3c3c3c3010,
            0x0e1e1e1e1e1e1e1e_1e1e1e1e1e1e1808,
            0x070f0f0f0f0f0f0f_0f0f0f0f0f0f0c04,
            0x0387878787878787_8787878787878602,
            0x01c3c3c3c3c3c3c3_c3c3c3c3c3c3c301,
            0xe1e1e1e1e1e1e1e1_e1e1e1e1e1e1e180,
            0x70f0f0f0f0f0f0f0_f0f0f0f0f0f0f0c0,
            0x3878787878787878_7878787878787860,
            0x1c3c3c3c3c3c3c3c_3c3c3c3c3c3c3c30,
            0x0e1e1e1e1e1e1e1e_1e1e1e1e1e1e1e18,
            0x070f0f0f0f0f0f0f_0f0f0f0f0f0f0f0c,
            0x0387878787878787_8787878787878786,
            0x01c3c3c3c3c3c3c3_c3c3c3c3c3c3c3c3,
            0xe1e1e1e1e1e1e1e1_e1e1e1e1e1e1e1e1,
            0x91f0f0f0f0f0f0f0_f0f0f0f0f0f0f0f0,
            0x48f8787878787878_7878787878787878,
            0x247c3c3c3c3c3c3c_3c3c3c3c3c3c3c3c,
            0x123e1e1e1e1e1e1e_1e1e1e1e1e1e1e1e,
            0x091f0f0f0f0f0f0f_0f0f0f0f0f0f0f0f,
            0xe58f878787878787_8787878787878787,
        ];

        for i in 0..GF128_FIELD_SIZE {
            assert_eq_hex!(
                EXPECTED_KEY1[i],
                expanded_key.0[i],
                "Mismatch at index {}",
                i
            );
        }
    }

    #[test]
    fn test_ghash() {
        crate::common::init();

        const HASH_INPUT_STRING: &str = "Hello SymCrypt";
        const RESULT0: Block = [0u8; GF128_BLOCK_SIZE];
        let mut hash_input = [0u8; GF128_BLOCK_SIZE];
        let bytes = HASH_INPUT_STRING.as_bytes();
        let len = bytes.len().min(GF128_BLOCK_SIZE);
        hash_input[..len].copy_from_slice(&bytes[..len]);

        const H0: Block = [0u8; GF128_BLOCK_SIZE];
        let key0: GHashExpandedKey = GHashExpandedKey::from(&H0);
        let mut ghash0 = super::GHash::new(&key0);
        ghash0.append(&hash_input);
        let result0 = ghash0.result();

        assert_eq_hex!(
            RESULT0,
            result0,
            "GHash result does not match expected value"
        );

        // Test with a different key
        const RESULT1: Block = [
            0x8e, 0xc7, 0xb1, 0xfe, 0x15, 0xfc, 0xf0, 0x0b, 0x83, 0xbd, 0xea, 0x2c, 0xa0, 0x8d,
            0x02, 0xd2,
        ];

        const H1: Block = [1u8; GF128_BLOCK_SIZE];
        let key1: GHashExpandedKey = GHashExpandedKey::from(&H1);
        let mut ghash1 = super::GHash::new(&key1);
        ghash1.append(&hash_input);
        let result1 = ghash1.result();

        assert_eq_hex!(
            RESULT1,
            result1,
            "GHash result does not match expected value"
        );
    }

    #[test]
    fn test_ghash_interop() {
        crate::common::init();

        let mut rng = rand::rng();
        let mut h = [0u8; GF128_BLOCK_SIZE];
        let mut input = [0u8; GF128_BLOCK_SIZE];

        for _i in 0..100 {
            rng.fill_bytes(&mut h);
            rng.fill_bytes(&mut input);

            // Simulate their GHASH computation
            let key = GHashExpandedKey::from(&h);
            let mut my_ghash = super::GHash::new(&key);
            my_ghash.append(&input);
            let my_result = my_ghash.result();

            // Simulate my GHASH computation
            let mut their_ghash =
                ghash::GHash::new_with_init_block(ghash::Key::from_slice(&h), 0u128);
            their_ghash.update_padded(&input);
            let their_result = their_ghash.finalize();

            assert_eq_hex!(
                their_result.as_slice(),
                my_result,
                "GHASH results do not match - input key {:?}, input data {:?}",
                h,
                input
            );
        }
    }
}
