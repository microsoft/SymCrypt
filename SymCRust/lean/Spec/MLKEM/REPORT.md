# FIPS 203 (ML-KEM) Specification

This file documents the formalization in `Spec/MLKEM`. See [`Properties/MLKEM/VERIFIED.md`](../../Symcrust/Properties/MLKEM/VERIFIED.md) for its implementation properties and [`README-VERIFIEDCRYPTO.md`](../../../../README-VERIFIEDCRYPTO.md) for context.

- **Standard**: [NIST.FIPS.203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) — *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, August 2024.

---

## 1. Files

| File | Contents |
|---|---|
| [`Spec.lean`](./Spec.lean) | FIPS 203 §2 (parameters, types), §4 (cryptographic functions, byte/bit encodings, NTT), §5 (K-PKE), §6 (internal ML-KEM), §7 (top-level ML-KEM). Every algorithm carries a section / equation reference back to the standard in its preceding doc-comment header. |
| [`Polynomials.lean`](./Polynomials.lean) | Pointwise/structural lemmas about `Vector (ZMod m) 256` used in Properties. |
| [`TestVectors.lean`](./TestVectors.lean) | 14 micro-tests (parameter sanity, ζ roots of unity, NTT round-trip on zero) run by `lake build`, plus NIST CAVP vectors for all three parameter sets. |

The FIPS 203 standard is not bundled in this branch; it is available from NIST at
[10.6028/NIST.FIPS.203](https://doi.org/10.6028/NIST.FIPS.203).

## 2. Building and testing the spec in Lean

```sh
cd SymCRust/lean
lake build Spec.MLKEM             # spec + Polynomials + 14 #guard checks
lake exe mlKemTests               # NIST CAVP vectors
```

Three layers of tests, all in [`TestVectors.lean`](./TestVectors.lean). The SymCrypt implementation is independently tested on a much larger scale.

| Layer | Count |
|---|---:|
| Compression / encoding round-trips, `BaseCaseMultiply` identities, NTT-on-zero, four named ζ powers from Appendix A | 14 |
| NIST CAVP key-generation vectors for ML-KEM-512, ML-KEM-768, ML-KEM-1024 | 3 |
| NIST CAVP encapsulation vectors for the same three parameter sets, run as `KeyGen → Encaps → Decaps` round-trips that also check the recovered shared secret | 3 |

--- 

## 3. Formalization notes and known deviations from FIPS 203

1. **NTT- and non-NTT-domain polynomials share one type.** Both `R_q`
   and `T_q` elements are `Vector (ZMod q) 256`; the domain
   distinction is carried by comment-only "hat" notation (`f̂`, `ŝ`,
   `Â`).
2. **Coefficient modulus is parameter-dependent.** `Polynomial d` is
   `Vector (ZMod m) 256` with `m = 2^d` for `d < 12` and `m = q` for
   `d = 12`.
3. **Randomness is abstracted, not modelled.** The `_internal`
   functions take random byte vectors as explicit inputs; the
   top-level `KeyGen` / `Encaps` thread a `RandomTape`
   (FIPS 203 §3.3 abstract RBG).
4. **`SampleNTT` is a `while` loop.** Algorithm 7 has no a priori iteration bound; the Lean version uses `Lean.Loop` (total by construction). Functional termination (`kyber_terminates` in [`Properties/MLKEM/Sampling/SampleNTT.lean`](../../Symcrust/Properties/MLKEM/Sampling/SampleNTT.lean)) reduces to the SHAKE128 stream-stability proved in [`Spec/SHA3/Termination.lean`](../SHA3/Termination.lean), itself built on the KECCAK-f bijection from [`Spec/SHA3/Permutation.lean`](../SHA3/Permutation.lean) (Barbosa–Schwabe 2023).
5. **Dependent `.cast` insertions.** Where parameter-dependent byte
   lengths require equating expressions like `384 * k` with
   `32 * 12 * k`, the spec inserts `Vector.cast` rather than reshape
   the algorithm. Semantics is unchanged.
6. **Input validation.** Type-level length checks (Algorithms 19–21)
   are by construction. The two algorithmic checks — encapsulation
   modulus check (§7.2, Eq. 7.1) and decapsulation key-hash check
   (§7.3) — are explicit in `Encaps_input_check` and
   `Decaps_input_check`.
7. **SHA-3 / SHAKE.** `H`, `J`, `G`, `PRF`, `XOF` route through the
   byte-level wrappers in [`Spec/SHA3/`](../SHA3/REPORT.md) and
   the incremental sponge in
   [`Spec/SHA3/XOF.lean`](../SHA3/XOF.lean).

Explicitly NOT formalized in this spec:

- **FIPS 203 §3.3 abstract RBG and §3.4 destroying intermediate
  values.** Cryptographic randomness and the deletion of stack
  intermediates are implementation-level concerns.
- **FIPS 203 §A (formulas for ζ) and §B (sampling rejection
  rates).** Mathematical justification; not algorithmic. The four
  ζ values used by the spec are checked by `#guard` (§2).
- **The IND-CCA security argument** (FIPS 203 §3.2 footnote, plus
  external literature). The Lean spec defines correctness only;
  cryptographic-security claims are not formalized here.

---

## 4. Coverage of FIPS 203

Every algorithm in FIPS 203 is formalized in
[`Spec.lean`](./Spec.lean). The in-file section headers carry the
exact FIPS reference and read top-down in standard order
(except Algorithm 12, defined before Algorithm 11 because the latter
calls it).

| FIPS 203 § | Standard name | Lean name |
|---|---|---|
| §2.4 / §8, Table 2 | Parameter sets ML-KEM-{512, 768, 1024} | `ParameterSet`, `q`, `n`, `ζ` |
| §4.1, Eq. 4.1–4.5 | H, J, G, PRF, XOF | `H`, `J`, `G`, `PRF`, `XOF` |
| §4.2.1 Alg 3 | `BitsToBytes(b)` | `BitsToBytes` |
| §4.2.1 Alg 4 | `BytesToBits(B)` | `BytesToBits` |
| §4.2.1, Eq. 4.7–4.8 | `Compress_d` / `Decompress_d` | `Compress`, `Decompress` |
| §4.2.1 Alg 5 | `ByteEncode_d(F)` | `ByteEncode` |
| §4.2.1 Alg 6 | `ByteDecode_d(B)` | `ByteDecode` |
| §4.2.2 Alg 7 | `SampleNTT(B)` | `SampleNTT` |
| §4.2.2 Alg 8 | `SamplePolyCBD_η(B)` | `SamplePolyCBD` |
| §4.3 Alg 9 | `NTT(f)` | `NTT` |
| §4.3 Alg 10 | `NTT⁻¹(f̂)` | `NTTInv` |
| §4.3.1 Alg 11 | `MultiplyNTTs(f̂, ĝ)` | `MultiplyNTTs` |
| §4.3.1 Alg 12 | `BaseCaseMultiply(a₀, a₁, b₀, b₁, γ)` | `BaseCaseMultiply` |
| §5.1 Alg 13 | `K-PKE.KeyGen(d)` | `K_PKE.KeyGen` |
| §5.2 Alg 14 | `K-PKE.Encrypt(ekPKE, m, r)` | `K_PKE.Encrypt` |
| §5.3 Alg 15 | `K-PKE.Decrypt(dkPKE, c)` | `K_PKE.Decrypt` |
| §6.1 Alg 16 | `ML-KEM.KeyGen_internal(d, z)` | `KeyGen_internal` |
| §6.2 Alg 17 | `ML-KEM.Encaps_internal(ek, m)` | `Encaps_internal` |
| §6.3 Alg 18 | `ML-KEM.Decaps_internal(dk, c)` | `Decaps_internal` |
| §7.1 Alg 19 | `ML-KEM.KeyGen()` | `KeyGen` |
| §7.2 Alg 20 + Eq. 7.1–7.2 | `ML-KEM.Encaps(ek)` + modulus check | `Encaps`, `Encaps_input_check` |
| §7.3 Alg 21 + Eq. 7.3 | `ML-KEM.Decaps(dk, c)` + hash check | `Decaps`, `Decaps_input_check` |

