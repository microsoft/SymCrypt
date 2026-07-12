# What is verified —  ML-KEM (FIPS 203)

This document presents verification results for the SymCrypt-Rust
ML-KEM implementation. It explains what is verified and gives
pointers to the formal counterpart in Lean.

See the top-level [`README-VERIFIEDCRYPTO.md`](../../../../../README-VERIFIEDCRYPTO.md)
for context, methodology, tooling, and trust assumptions.

---

## 1. Scope

- **Specification**: `SymCRust/lean/Spec/MLKEM/Spec.lean`, a direct
  formalization of
  [NIST FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
  ("Module-Lattice-Based Key Encapsulation Mechanism Standard",
  August 2024), annotated with FIPS section and algorithm numbers. 
  Sanity checks include basic properties and CAVP/ACVP roundtrip tests 
  (KeyGen + Encaps + Decaps) for each parameter set.
  
- **Implementation**: the `mlkem` module of the SymCrypt-Rust crate
  (`SymCRust/src/mlkem/{ffi,hash,key,mlkem,ntt}.rs`) including
    multi-target SIMD bodies for the NTT layer (`ntt_xmm`,
  `ntt_neon`, `ntt_avx2`), but excluding tests.

- **Parameter sets**: ML-KEM-512, ML-KEM-768, ML-KEM-1024. All three
  are verified simultaneously: most specs and proofs are parametric in
  the security level.

- **Verification**: every public function (see §3) is verified against
  FIPS 203 under the trust assumptions listed in §6.
    
- **Out of scope**:
  - Performance, side-channel resistance, and constant-time properties.
  - Cryptographic security of FIPS 203 itself (the standard is
    treated as the trusted reference).
  - Raw-pointer aliasing through `Box::new_uninit` for the three
    allocators (`Key`, `InternalComputationTemporaries`,
    `DecapsulateTemps`) — outside the Aeneas memory model;
    axiomatised per-instance (see §6).

---

## 2. From Rust to Lean — how the proofs are organised

Using the Rust → Charon → Aeneas → Lean pipeline, all SymCrypt-Rust code subject to
verification (for all algorithms including ML-KEM) is mechanically translated to Lean
definitions under `SymCRust/lean/Symcrust/Code/`. The translation of every Rust function is then equipped with an
`@[step]`-tagged theorem with precise pre- and post-conditions expressed using the Spec.

The file layout under `Properties/MLKEM/` (LOC = `cloc` non-comment, non-blank source lines):

| Path | LOC | Contents |
|---|---:|---|
| `Basic.lean` + `Basic/` | 284 | Abstraction functions (`toPoly`, `toMontPoly`, `paramsToSpec`) and well-formedness predicates (`wfKey`, `wfPolyVec`, `wfPoly`) |
| `Bridges/` | 7,288 | Lemmas relating Code and Spec representations: `MontArith`, `ModArith`, `NttLoops`, `NttLinearity`, `Encoding`, `EncodingStreamCompress`, `EncodingStreamDecompress`, `MatrixVectorMul`, `KeyView`, `PrfShake` |
| `Ntt/` | 5,636 | Polynomial arithmetic, forward/inverse NTT, matrix-vector multiply |
| `Sampling/` | 3,152 | `SampleNTT` (matrix-A generation), `SampleCBD` (centered binomial distribution), `ExpandMatrix` (matrix from public seed) |
| `Encoding/` | 8,213 | Compress/Decompress, KeySetValue, KeyGetValue |
| `Hash.lean` + `HashCalls.lean` | 575 | SHA-3/SHAKE adaptors (H, J, G, PRF, XOF) |
| `Helpers/` | 1,138 | Shake128 byte bridge, KPKE structural lemmas, slice/append helpers |
| `Intrinsics/` | 4,636 | Parametric Vec128 NTT/INTT layer specs (`Vec128Layer{Ntt,Intt}`), AVX2 layer (`Avx2Layer{Ntt,Intt}`), and per-arch instances (`X86_64/Sse2`, `Aarch64/Neon`) |
| `Axioms/` | 45 | `BoxDefault` (per-instance `try_new_box_default` specs) |
| `Key.lean` + `Key/`, `KeyGen.lean`, `Encaps.lean` + `Encaps/`, `Decaps.lean`, `Ffi.lean` | 6,690 | Key construction chain (load + expand), top-level `KeyGen` / `Encaps` / `Decaps`, FFI shims |
| `Workflow.lean` | 248 | End-to-end key-generate → encapsulate → decapsulate round-trip spec |
| **Total** | **37,973** | (incl. the `MLKEM.lean` aggregator and `AeneasExtras.lean`) |

---

## 3. Verified API 

The following functions form the public surface of `mlkem`.


### 3.1. Algorithmic entry points (FIPS 203 §7)

The main functions are proved correct with regard to the corresponding Spec algorithms, as explained in §4.

| Rust function | Lean theorem | Standard reference (FIPS 203) |
|---|---|---|
| [`key_generate`](../../../../src/mlkem/mlkem.rs) | `mlkem.key_generate.spec` in [`KeyGen.lean`](./KeyGen.lean) | `KeyGen` (Alg. 19) |
| [`encapsulate`](../../../../src/mlkem/mlkem.rs) | `mlkem.encapsulate.spec` in [`Encaps.lean`](./Encaps.lean) | `Encaps` (Alg. 20) |
| [`encapsulate_ex`](../../../../src/mlkem/mlkem.rs) | `mlkem.encapsulate_ex.spec` in [`Encaps.lean`](./Encaps.lean) | `Encaps_internal` (Alg. 17) |
| [`decapsulate`](../../../../src/mlkem/mlkem.rs) | `mlkem.decapsulate.spec` in [`Decaps.lean`](./Decaps.lean) | `Decaps` (Alg. 21) |
| [`key_set_value`](../../../../src/mlkem/mlkem.rs) | `mlkem.key_set_value.spec` in [`Encoding/KeySetValue.lean`](./Encoding/KeySetValue.lean) | `K_PKE.KeyGen` (Alg. 13) for `PrivateSeed`; reconstruction of `ek`/`dk` for `EncapsulationKey`/`DecapsulationKey` formats |
| [`key_get_value`](../../../../src/mlkem/mlkem.rs) | `mlkem.key_get_value.spec` in [`Encoding/KeyGetValue.lean`](./Encoding/KeyGetValue.lean) | Key serialization to the three FIPS-203-defined formats |


### 3.2. Size queries and parameter dispatch (FIPS 203 §6)

Five `pub fn` size queries (`sizeof_key_format_from_params`,
`sizeof_ciphertext_from_params`, and three `mlkem::ffi::sizeof_*`
internal helpers, all in `Ffi.lean`) have step specs that return
the FIPS 203 §6 byte sizes for keys and ciphertexts. 

### 3.3. NTT primitives (FIPS 203 §4.3)

The forward and inverse Number-Theoretic Transform are exposed at
the crate level for use inside the algorithmic entry points above.
Their theorems state the correctness of the in-place transform to the
Spec functional form (with the implementation's Montgomery
scaling factored out by `Bridges/MontArith.lean`).

| Rust function | Lean theorem |
|---|---|
| [`ntt::poly_element_ntt`](../../../../src/mlkem/ntt.rs) | [`Ntt/Ntt.lean`](./Ntt/Ntt.lean) |
| [`ntt::poly_element_intt_and_mul_r`](../../../../src/mlkem/ntt.rs) | [`Ntt/Intt.lean`](./Ntt/Intt.lean) |

Per-target dispatchers (`poly_element_{ntt,intt}_layer.{x86_64,
i686,aarch64}_unknown_linux_gnu`) plus the parametric
`*_vec128` (SSE2/NEON) and `*_avx2` layer functions are all in
scope at the spec level. The SSE2 (`xmmNttIntrinsicsSpec`,
`X86_64/Sse2`), NEON (`neonNttIntrinsicsSpec`, `Aarch64/Neon`)
and AVX2 (`Avx2LayerNtt`, `Avx2LayerIntt`) instances are fully
proved against their per-lane Montgomery-arithmetic specs, with the
load / store / set / add-sub-mod-q / Montgomery wrappers all proven
theorems (no ML-KEM-specific axioms). The underlying silicon intrinsics
they bottom out on are each specified against a pure-Rust **model** in
`src/verify/intrinsics/{x86_64/{sse2,xmm,avx2,ymm},aarch64/neon}.rs`,
and every model is differentially tested against the real hardware
intrinsic — `shim(x) == core::arch::<arch>::<intrinsic>(x)` on
SDM/ARM-ARM-branch-covering inputs — by the harnesses
`src/verify/tests/{x86_64_sse2_hw_extras,x86_64_avx2_hw,x86_64_ymm_hw,
aarch64_neon_hw}.rs` (methodology §1 P7). The Lean opcode specs in
`Intrinsics/Axioms/**` pin those tested-model semantics; these
opcode axioms are a separate trust surface (the Intrinsics row in
the top-level `README-VERIFIEDCRYPTO.md`), not part of the ML-KEM
entry-point closure — see the note in §6.

### 3.4. C ABI shims (`mlkem/ffi.rs`)

The functions in `src/mlkem/ffi.rs` 
are thin `extern "C"` shims around the Rust functions above (e.g.
`SymCryptMlKemEncapsulate` unwraps the C pointer/length pair and
delegates to `mlkem::encapsulate`). 

---

## 4. Main Theorems 

This section summarizes the theorem for each algorithmic entry point in §3.1.

### 4.0. Notations

- `params : ParameterSet` is one of the parameter sets
(`ML_KEM_512 | ML_KEM_768 | ML_KEM_1024`) and `k params` 
is the corresponding matrix dimension (2, 3, 4).

- `self : Key` is the opaque key container of the C/Rust API. 
  
- Callers allocate a fresh `Key` then pass it to 
  `key_generate` (sample from randomness) or `key_set_value` (import), 
  `encapsulate`, `decapsulate`, and `key_get_value` (export).

- `wfKey self params` is its structural well-formedness invariant, 
  established by the constructor `mlkem.key.key_allocate.spec`
  and preserved by all other functions. 
  
- `wfEncapKey self params` (`Sampling/ExpandMatrix.lean`) is the
  **public-key invariant**, strengthening `wfKey self params` 
  with three properties —
  - `hash_pinned`: `self.encaps_key_hash = SHA3-256(ek)` where
    `ek = encoded_t[0..384·k] ‖ public_seed` (FIPS 203 §7.2 line 1).
  - `byte_form_t`: the encoded-`t̂` prefix is the canonical 12-bit
    `ByteEncode` of a `PolyVector q k` view of the key.
  - `matrix_form_a`: every `keyAHat[i, j]` equals
    `SampleNTT(ρ ‖ i ‖ j)` (FIPS 203 Alg. 13 line 6).

  `wfEncapKey` is the precondition of `encapsulate`
  and `encapsulate_ex`. It is produced (in NoError branches) by
  `key_set_value` on the `EncapsulationKey` format, and (via
  `wfEncapKey_of_wfDecapKey`) by `key_generate` and by `key_set_value`
  on the `PrivateSeed` / `DecapsulationKey` formats.

- `wfDecapKey self params` is the **private-key invariant**, 
  extending `wfEncapKey self params` with `self.has_private_key = true`.
  Consumed by `decapsulate`. Produced by `key_generate`,
  `key_set_value(PrivateSeed)`, and `key_set_value(DecapsulationKey)`.

- `wfPrivateSeed self params` is the **private-seed invariant**,
  strengthening `wfDecapKey self params` with `self.has_private_seed = true`
  and the property that all coefficient slots (`Â`, `t`, `s`) are
  consistent with key generation.
  (FIPS 203 Alg. 19).  Produced by `key_generate` and by
  `key_set_value(PrivateSeed)`; consumed by `key_get_value(PrivateSeed)`
  as evidence that the seed bytes can be exported.

- `Format.length params format` gives the byte lengths of every key format.
  and `wfKeyFormat self format params` is the format-parametric
  well-formedness property for serialized keys.
  
- `Key.toSpec self format params` extracts key values from key containers 
  in specifications.
  
- `RandomTape` models the randomness that top-level entries
  draw from `common::random` (an opaque external — see §6.1). 
  It is underspecified, i.e., their main theorems are of the form
  "there exists a `tape` such that the
  runtime output equals `Spec.MLKEM.<Algorithm> params tape`".
  
### 4.1. [`mlkem.key_generate.spec`](./KeyGen.lean)

The Rust function `key_generate` takes a well-formed `Key` and a `flags` word, samples a fresh ML-KEM
key pair from `common::random`, and writes it into `Key`.

Its theorem says that, in the absence of error, 
(1) the function establishes `wfPrivateSeed self params`, the strongest key invariant;
and (2) there exists a `RandomTape` `tape` such that the 
key-generation algorithm `KeyGen params tape` returned the keypair `(ek,dk)` 
held in-memory: 
- the key's encapsulation-key view equals `ek`;
- the key's encoded `s` slot equals the first `384·k` bytes of `dk`. 

The theorem also documents 3 errors and their cause: 

- `InvalidArgument` when the flags are incorrect. 
- `FipsFailure` when `flags &&& FLAG_KEY_NO_FIPS = 0#u32`, reflecting
  that in FIPS mode the self-test might fail (with negligible probability).  
- `MemoryAllocationFailure` when `out_of_memory` allocating temporaries.

### 4.2. [`mlkem.encapsulate_ex.spec`](./Encaps.lean)

The Rust function `encapsulate_ex` implements the **deterministic** 
encapsulation entry point (FIPS 203 Algorithm 17, `Encaps_internal`). 
It takes the encapsulation key (wrapped in a `Key` container), the random
message `m : [u8; 32]` explicitly as input rather than drawing it
internally, an output buffer for the agreed secret, and an output
buffer for the ciphertext. On success it writes both.

The precondition is `wfEncapKey pk_mlkem_key params`, ensuring 
the three crypto-level commitments — `hash_pinned`, `byte_form_t`, `matrix_form_a` —
have already been established and need not be re-checked on every call. 

On `NoError`, the postcondition states that the function 
outputs the same results as the specification: 
`agreed_secret' = K` and `ciphertext = c`.

Errors range over `InvalidArgument` on length mismatches on the agreed-secret 
and ciphertext output buffers, and `MemoryAllocationFailure` when 
allocating internal computation temporaries.

### 4.3. [`mlkem.encapsulate.spec`](./Encaps.lean)

The Rust function `encapsulate` is a **randomised** wrapper over
`encapsulate_ex`: it draws the 32-byte message from `common::random`
then runs the deterministic core. Accordingly, its `NoError`
postcondition is stated with an outer existential `RandomTape` witness,
and matches the specification result (`MLKEM.Encaps`).

### 4.4. [`mlkem.decapsulate.spec`](./Decaps.lean)

The Rust function `decapsulate` takes a key, a
ciphertext, and an output buffer; on success it writes the agreed
secret.

Its precondition is `wfDecapKey pk_mlkem_key params`.

On `NoError`, its postcondition states that the implementation 
returns the same secret as the specification (FIPS 203 Algorithm 21).

This implies in particular that the function correctly implements 
ML-KEM's implicit rejection: if the ciphertext does not
re-encrypt to the decrypted polynomial, the constant-time selection
returns the SHAKE256(z‖c)-derived implicit-reject secret K̄ rather
than K′ (FIPS 203 Alg. 21, lines 7–9).

Errors include `InvalidArgument` on length mismatches and 
`MemoryAllocationFailure` on `out_of_memory` when allocating 
the decapsulation temporaries.

### 4.5. [`mlkem.key_set_value.spec`](./Encoding/KeySetValue.lean)

The function `key_set_value` takes bytes in one of
three FIPS-203-defined formats: `PrivateSeed`, `EncapsulationKey`,
or `DecapsulationKey`. 

If the call succeeds, the postcondition yields 
the corresponding key invariant, so that callers can chain e.g. 
`key_set_value → encapsulate` and 
`key_set_value → decapsulate`.

The call may also return an error: 
- `WrongKeySize` when the input length doesn't match the
format's expected size.
- `InvalidArgument` when either a bit outside
`FLAG_KEY_NO_FIPS | FLAG_KEY_MINIMAL_VALIDATION` is set, or
`FLAG_KEY_MINIMAL_VALIDATION` is set while `FLAG_KEY_NO_FIPS` is
unset (FIPS mode forbids skipping validation).
- `InvalidBlob` when 
`EncapsulationKey`/`DecapsulationKey` content validation fails
(the canonical-12-bit-encoding range check on the encoded `t` /
`s`, and the hash mismatch on `DecapsulationKey`).
- `MemoryAllocationFailure` when `out_of_memory` 
  allocating the internal computation temporaries for key expansion.

### 4.6. [`mlkem.key_get_value.spec`](./Encoding/KeyGetValue.lean)

`key_get_value` is the inverse: it serialises a key into
a byte blob in any of the three formats. 

The precondition requires that the key contents 
be compatible with the requested output format.

The postcondition states the correctness of the output bytes. 

Since, intuitively, the function trusts the in-memory key, 
the reachable error set is narrower:
- `WrongKeySize` for output length mismatch on `PrivateSeed`;
- `InvalidArgument` for output length mismatch on `EncapsulationKey` or 
`DecapsulationKey`.

---

## 5. NTT correctness (FIPS 203 §4.3)

The Number-Theoretic Transform is the algorithmic core of ML-KEM
and the part of the code with the most divergence between the
spec (a functional fold over twiddle-factor butterflies) and the
implementation (in-place butterflies with Montgomery-form
operands, optionally vectorised through SSE2 / NEON / AVX2).

`Bridges/MontArith.lean`, `Bridges/NttLoops.lean`, and
`Bridges/NttLinearity.lean` establish:

- **Montgomery cancellation**: the implementation stores
  polynomial coefficients premultiplied by `R = 2¹⁶ mod q = 2285`
  throughout the NTT pipeline; the conversion `Rinv = 169`,
  proved by `R * Rinv = 1` in `ZMod q`, is applied on output
  paths. Every `@[step]` postcondition is stated in the standard
  domain via `Basic.toPoly`, with Montgomery-domain operands
  converted back via `toMontPoly` and the cancellation lemmas
  from `MontArith.lean`.
- **Loop / leaf factoring**: `Bridges/NttLoops.lean` exposes the
  recursive loop layers of the implementation as a single
  spec-level fold over the FIPS-203 butterfly schedule, modulo
  the Montgomery factor.

`Ntt/MulAccum.lean` and `Ntt/MatVec.lean` verify the
multiply-and-accumulate primitive used by Â·ŝ + ê (KeyGen) and
Â·r̂ (Encaps). The non-trivial accumulator obligation
`debug_assert!(c1 < 5·M + 3·A)` is discharged via an
**asymmetric loop invariant**: even-index slots carry the loose
bound `pa[2j] ≤ K·(M+A)`, odd-index slots carry the tight bound
`pa[2j+1] ≤ K·2·M`, and the slack `3·(A − M) = 881,676` clears
the assert.

For the SIMD layers (`*_vec128`, `*_avx2`), the per-lane
Montgomery-arithmetic specs are proved at the algorithmic level
(`Intrinsics/Vec128Layer*.lean`, `Intrinsics/X86_64/Avx2Layer*.lean`).
The per-arch load / store / set / add-sub-mod-q / Montgomery wrappers in
`Intrinsics/{X86_64/Sse2,Aarch64/Neon}.lean` and
`Intrinsics/X86_64/Avx2LayerNtt.lean` are themselves **proven theorems**
(no ML-KEM-specific axioms); the only silicon trust is the generic
per-opcode axioms in `Intrinsics/Axioms/**`. See §6 and §7.

---

## 6. Trust footprint (axioms the proofs depend on)

This section lists every **project-local** `axiom` the verified
surface transitively depends on — those declared under
`Properties/Axioms/` and `Properties/MLKEM/Axioms/`. They fall into
three categories: stdlib / memory-model primitives outside Aeneas's
model (§6.1), an almost-sure-termination claim for the
rejection-sampling loop (§6.2), and target / CPU-dispatch queries
(§6.3). Beyond these, the closure bottoms out only on a few opaque
**Aeneas-stdlib** axioms (raw-pointer ops `RawPtrMutT.cast`/`is_null`,
box allocation `Box.from_raw` / `alloc_zeroed` / `Layout.new`, and
`core.fmt.Formatter`), which are part of the trusted Charon/Aeneas
toolchain rather than a project surface. The SIMD paths add
no axioms: under `--features verify` the NTT proofs run against the
pure-Rust intrinsic *models*, so no silicon opcode axiom enters the
entry-point closure (the silicon `Axioms/**` are a separate,
independently validated trust surface — see the Intrinsics row in
the top-level `README-VERIFIEDCRYPTO.md`).

### 6.1. Operational primitives outside the Aeneas memory model

- **`Properties/MLKEM/Axioms/BoxDefault.lean`** — three
  per-instance specs for `Box::<T>::default()` on the workspace
  types `Key`, `InternalComputationTemporaries`, and
  `DecapsulateTemps`, whose `Box::new_uninit + assume_init +
  zeroed` allocation pattern is not modelled by Aeneas. `Ok`
  branches yield a zero-initialised structure (carrying `wfKey`
  with both flags `false` on the `Key` instance); `Err` branches
  are tightened to `MemoryAllocationFailure ∧ out_of_memory`,
  where `out_of_memory` (declared in `Properties/Axioms/System.lean`)
  is the opaque allocator-failure witness propagated up to the
  top-level `MemoryAllocationFailure` arms of `key_allocate`,
  `key_set_value`, `encapsulate(_ex)`, `decapsulate`, and
  `key_generate`. Trust ground: Rust stdlib allocator contract.

- **`Properties/Axioms/System.lean :: random.spec`** — opaque
  cryptographic RNG, with post `err = NoError ∧ out.length =
  requested.length`. The FIPS-203 random tape is reconstructed
  consumer-side by `key_generate.spec` and `encapsulate.spec`
  via outermost `∃ tape : RandomTape` clauses.

- **`Properties/Axioms/System.lean :: common.try_new_box_zeroed.spec`**
  — generic counterpart of `BoxDefault` for the PCT scratch buffer
  in `key_generate`; its `Err` arm likewise yields
  `MemoryAllocationFailure ∧ out_of_memory`.  This file also declares
  the opaque `out_of_memory : Prop` witness shared by all
  box-allocation axioms.

- **`Properties/Axioms/Stdlib.lean`** — three `@[step] axiom`
  specs for functions Aeneas emits as opaque declarations:
  `common.Error.ne` (decidable inequality on the project-specific
  error enum), and the two `#[verify::opaque]` constant-time
  helpers `common.const_time_slices_equal_impl` (equal-length byte
  slice equality) and `common.const_time_slice_copy_impl`
  (conditional slice copy). The latter two perform constant-time
  comparison / conditional copy through raw-pointer volatile reads
  and writes; only their value-level behaviour is postulated, the
  constant-time property is out of scope. (Generic stdlib
  operations — `Array.as_ref` / `Array.as_mut`, `Slice.fill`,
  scalar casts — are now modelled in the Aeneas stdlib and no
  longer need project-local axioms.)

- **`Properties/Axioms/Wipe.lean :: common.wipe_slice.spec`** —
  models `core::ptr::write_volatile` zeroisation on temp buffers
  and `Key.wipe_private_state`.

### 6.2. Almost-sure termination

- `Sampling/SampleNTT.lean :: kyber_terminates` — the
  existential `∀ B, ∃ n, (sampleNttPartial B n).2 = 256`.
  FIPS 203's `SampleNTT` rejection-sampling loop is only
  *almost-surely* terminating (Barbosa & Schwabe, "Kyber
  Terminates", 2023); no constructive bound is known, and the
  EasyCrypt ML-KEM proof leaves the same gap. The obligation is
  split into this narrow termination claim plus the mechanically
  proved `sampleNttPartial_full_eq_SampleNTT`.

- A single equational axiom remains in `Properties/Axioms/Iterators.lean`:
  `Loop_forIn_Id_unfold` — unconditional unfold of
  `@Lean.Loop.forIn _ Id _ Lean.Loop.mk b f`, used at two `rw`
  sites in `Sampling/SampleNTT.lean`. Lean 4.30-rc2's
  `Lean.Loop.forIn` is a `partial def` without an exposed
  equation lemma.
  
### 6.3. Target and CPU-dispatch queries

- `Properties/Axioms/System.lean :: common.cpu_features_present`
  and `std_detect.detect.arch.x86.__is_feature_detected.avx2`
  — `@[step] axiom` specs (post `⦃ _ => True ⦄`) for the runtime
  CPU-feature queries used by the per-architecture NTT dispatcher
  to select between AVX2, SSE2, NEON, and portable
  implementations. The dispatcher proof discharges both branches
  of the resulting `if`, so an opaque CPU-feature query cannot
  falsify FC of either path.

- `Properties/Axioms/Target.lean :: get_target` / `theTarget` —
  the compile-time build-target counterpart of the queries above.
  `theTarget` is a bodyless opaque `Std.Str` and `get_target.spec`
  postulates that the `rustc --target` query returns it; the
  per-architecture dispatcher branches on this fixed value to select
  the multi-target SIMD body. A local override so the proofs see a
  single stable target rather than a runtime-varying one; as with the
  CPU-feature queries, the dispatcher proof covers every branch.

---

## 7. Building and inspecting the proofs

The top-level [`README-VERIFIEDCRYPTO.md`](../../../../../README-VERIFIEDCRYPTO.md)
§4 documents the full build pipeline (C+Rust build, Rust tests, Aeneas
extraction, full Lean build). The commands below assume that pipeline
has been run at least once and the Aeneas-extracted `Code/` is present.

```sh
cd SymCRust/lean

# Build the ML-KEM proofs only (incremental; seconds after a warm build).
lake build Symcrust.Properties.MLKEM

# Spec-side sanity check (#guard examples; fast).
lake build Spec.MLKEM

# Spec-side CAVP / ACVP round-trip on all three parameter sets.
lake exe mlKemTests

# List the axioms a given top-level proof depends on.
lake env lean -e '
  import Symcrust.Properties.MLKEM
  open Symcrust.Properties.MLKEM
  #print axioms mlkem.encapsulate.spec
  #print axioms mlkem.decapsulate.spec
  #print axioms mlkem.key_generate.spec
'
```

Each top-level theorem's `#print axioms` output corresponds to the
union of categories in §6.1–6.3 plus `propext`, `Classical.choice`,
`Quot.sound` (Lean's standard kernel axioms, shared with all of
Mathlib).

---

## 8. References

- **NIST FIPS 203** — *Module-Lattice-Based Key-Encapsulation
  Mechanism Standard*, August 2024.
  Public URL: [NIST.FIPS.203.pdf](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
  (DOI [10.6028/NIST.FIPS.203](https://doi.org/10.6028/NIST.FIPS.203)).
- **NIST ACVP / CAVP** — `unittest/kat_kem.dat` (ACVP
  ML-KEM-keyGen-FIPS203 and ML-KEM-encapDecap-FIPS203
  vectors). Replayed in `Spec/MLKEM/TestVectors.lean`.
- **M. Barbosa, P. Schwabe**, *Kyber Terminates*, 2023 — the
  reference for the almost-sure-termination proof for §6.2.
