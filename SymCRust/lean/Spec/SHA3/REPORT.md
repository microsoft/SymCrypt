# FIPS 202 (SHA-3 / SHAKE) Specification

This file documents the formalization in `Spec/SHA3`. See [`Properties/SHA3/VERIFIED.md`](../../Symcrust/Properties/SHA3/VERIFIED.md) for its implementation properties and [`README-VERIFIEDCRYPTO.md`](../../../../README-VERIFIEDCRYPTO.md) for context.

- **Standard**: [NIST.FIPS.202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) — *SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions*, August 2015.

---

## 1. Files

| File | Contents |
|---|---|
| [`Spec.lean`](./Spec.lean) | FIPS 202 §2–§6: types, step mappings (θ/ρ/π/χ/ι), `KECCAK-p`/`KECCAK-f`, `SPONGE`, padding, the four SHA-3 functions, the two SHAKE XOFs, and the byte-level wrappers. |
| [`Properties.lean`](./Properties.lean) | Proved theorems *about* the spec (FIPS-internal sanity checks plus byte/bit lemmas reused by `Properties/SHA3/`). |
| [`Permutation.lean`](./Permutation.lean) | Inverse step-mappings (θ⁻¹, ρ⁻¹, π⁻¹, χ⁻¹, ι⁻¹) and a proof that `KECCAK_f` is bijective. |
| [`Termination.lean`](./Termination.lean) | Stream-stability theorems for `SHAKE128` (every output-byte cycle absorbs zero bits), built on `Permutation.lean`. Consumed by ML-KEM's `SampleNTT` termination proof (Barbosa–Schwabe 2023). |
| [`XOF.lean`](./XOF.lean) | Incremental sponge API (`init → absorb → squeeze*`). **Not a FIPS 202 construct** — bridge specification used by the Rust verification to model the `KeccakState` software pattern. |
| [`XOFProperties.lean`](./XOFProperties.lean) | Proved equivalence between the incremental and functional sponges (`squeeze1_init_eq_SPONGE_squeeze`). Internal infrastructure. |
| [`TestVectors.lean`](./TestVectors.lean) | 10 KAT micro-tests covering every variant — see §2. |

The FIPS 202 standard is not bundled in this branch; it is available from NIST at
[10.6028/NIST.FIPS.202](https://doi.org/10.6028/NIST.FIPS.202).

## 2. Building and testing the spec in Lean

```sh
cd SymCRust/lean
lake build Spec.SHA3                # spec + Properties + 10 #guard checks
```

10 KATs in [`TestVectors.lean`](./TestVectors.lean) assert as `#guard` expressions, so a regression fails `lake build`. Sources: NIST example pages and the FIPS 202 KAT companion files. The SymCrypt implementation is independently tested on a much larger scale.

| Variant | Coverage | Count |
|---|---|---:|
| SHA3-224 | empty message; "abc" | 2 |
| SHA3-256 | empty message; "abc" | 2 |
| SHA3-384 | empty message; "abc" | 2 |
| SHA3-512 | empty message; "abc" | 2 |
| SHAKE128 | empty message, 256-bit output | 1 |
| SHAKE256 | empty message, 512-bit output | 1 |

---

## 3. Formalization notes and known deviations from FIPS 202

The complete mechanization notes block lives at the top of [`Spec.lean`](./Spec.lean). The reviewer-relevant items:

1. **`b = 1600` specialization.** Only the SHA-3-relevant width is formalized. The other KECCAK-p widths in FIPS 202 Table 1 (`b ∈ {25, 50, 100, 200, 400, 800}`) are not used by SHA-3 and are out of scope.
2. **LSB-first bit ordering.** Lanes use `Vector Bool 64` with index 0 = LSB, matching the FIPS 202 lane-bit convention (§B.1). A scoped `OfNat` override makes numeric literals LSB-first so that, e.g., `(1 : Vector Bool 8)` has bit 0 = true.
3. **Lane-level operations.** χ uses `~~~` (complement) and `&&&` (AND) on lanes rather than per-bit `⊕ 1` and `·`; ρ uses `Bits.rotateLeft` instead of per-bit index arithmetic. Each reduces to the per-bit definition; the choice keeps the spec compact and matches how lane operations are stated in practice.
4. **`SPONGE` takes pre-padded input.** `SPONGE` is defined faithful to §4 Algorithm 8 over an already-padded bit string; the padding step is performed by `KECCAK` (§5.2), which prepends `N ‖ pad10*1(r, len(N))` before calling `SPONGE`. This isolates `SPONGE` from the dependently-typed padding length.
5. **`Pᵢ ‖ 0^c` uses `Bits.zeroExtend b`.** Because `c + r` is not definitionally `b` in Lean, the appended zeros are introduced via `Vector.zeroExtend` rather than literal concatenation; the semantics is unchanged.
6. **Loop bounds.** FIPS uses inclusive bounds ("for t from 0 to 23"); Lean `for t in [0:24]` uses exclusive upper bounds. The ranges are identical (`{0, 1, …, 23}`).
7. **Table 2 cross-checked.** The ρ offsets are transcribed as `ρ.Offsets` and proved equal to Algorithm 2's recurrence by `native_decide` in [`Properties.lean`](./Properties.lean) (`rhoOffsets_eq_table2`). Following the standard, the spec does not use the pre-computed round constants either: `ι.RC` evaluates Algorithm 6 directly via the LFSR `rc`.

Explicitly NOT formalized in this spec (the Rust implementation under audit does not use them):

- **KECCAK-p at widths other than 1600.** Only `b = 1600` (FIPS 202 Table 1).
- **`h2b` / `b2h` byte ⇄ bit-string conversions of §B.1.** Replaced with `bytesToBits` / `bitsToBytes` from [`Spec/Defs.lean`](../Defs.lean) (functionally identical; the Defs version is shared across all algorithms in this project).
- **Informative annexes (§7, §A).** Prose-only material with no algorithmic content.
- **cSHAKE / TupleHash / ParallelHash / KMAC** (NIST SP 800-185 derivatives). Not part of FIPS 202 and not used by SymCrypt-Rust.
- **Collision-, preimage-, and second-preimage-resistance claims** for the SHA-3 functions, and the indifferentiability of the sponge construction (FIPS 202 §A, plus the Keccak team's published analyses). The Lean spec defines the functions; cryptographic-security claims are not formalized here.

The incremental sponge API in [`XOF.lean`](./XOF.lean) is **not a FIPS 202 construct**: it models the Rust `KeccakState` software pattern and is proved equivalent to the functional `SPONGE` in [`XOFProperties.lean`](./XOFProperties.lean) (`squeeze1_init_eq_SPONGE_squeeze`). It is bridge infrastructure for the Rust proofs, not a spec for review.

---

## 4. Coverage of FIPS 202

Every algorithm and named construct of FIPS 202 is formalized in [`Spec.lean`](./Spec.lean). The in-file section headers carry the exact FIPS reference and read top-down in standard order.

| FIPS 202 § | Standard name | Lean name |
|---|---|---|
| §2.3 | `Trunc_s(X)` | `Trunc` |
| §2.3 | `X ‖ Y` concatenation | scoped `‖` from `Spec.Defs` |
| §3.1.1 | Lanes (`b = 1600`, `w = 64`, `ℓ = 6`) | `b`, `w`, `ℓ`, `Lane`, `State` |
| §3.1.2 | String → State | `stringToState` |
| §3.1.3 | State → String | `stateToString` |
| §3.2.1 Alg 1 | θ | `θ` |
| §3.2.2 Alg 2 + Table 2 | ρ (with offsets) | `ρ`, `ρ.Offsets` |
| §3.2.3 Alg 3 | π | `π` |
| §3.2.4 Alg 4 | χ | `χ` |
| §3.2.5 Alg 5 | `rc(t)` | `rc` |
| §3.2.5 Alg 6 | ι (+ round constants) | `ι.RC`, `ι` |
| §3.3 Alg 7 | `KECCAK-p[b, n_r]` | `KECCAK_p` (with `Rnd = ι ∘ χ ∘ π ∘ ρ ∘ θ`) |
| §3.4 | `KECCAK-f[1600]` | `KECCAK_f` |
| §4 Alg 8 | `SPONGE[f, pad, r](N, d)` | `SPONGE`, `SPONGE.absorb`, `SPONGE.squeeze` |
| §5.1 Alg 9 | `pad10*1(x, m)` | `«pad10*1»`, `padLen` |
| §5.2 | `KECCAK[c]` | `KECCAK` |
| §6.1 | SHA3-{224,256,384,512} | `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512` |
| §6.2 | SHAKE128, SHAKE256 | `SHAKE128`, `SHAKE256` |
| §6.3 | RawSHAKE128, RawSHAKE256 | `RawSHAKE128`, `RawSHAKE256` |
| §B.1 (byte interface) | byte-vector wrappers | `sha3_224/256/384/512`, `shake128`, `shake256` |
