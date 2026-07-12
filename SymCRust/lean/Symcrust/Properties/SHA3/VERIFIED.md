# What is verified — SHA-3 / SHAKE (FIPS 202)

This file presents verification results for the SymCrypt-Rust implementation of the SHA-3
family of cryptographic hash functions. It explains what is verified and gives
pointers to the formal counterpart in Lean.

See the top-level [`README-VERIFIEDCRYPTO.md`](../../../../../README-VERIFIEDCRYPTO.md)
for context, methodology, tooling, and trust assumptions.

---

## 1. Scope

- **Specification**: `SymCRust/lean/Spec/SHA3/Spec.lean`, a direct
  Lean formalization of [NIST.FIPS.202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
 "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions", August 2015.
  Spec definitions and lemmas are annotated with the matching FIPS section /
  algorithm numbers. Sanity checks include a proof that keccak is a permutation and
  CAVP/ACVP test vectors for SHA3-224/256/384/512 and SHAKE128/256.

- **Implementation**: the `sha3` module of the SymCrypt-Rust crate
  (`SymCRust/src/sha3/`), excluding tests. This covers the scalar 
  Keccak-f[1600] permutation, the byte-level sponge state machine
  (`sha3_impl.rs`), and the user-facing const-generic trait
  wrappers (`{sha3,shake}_variants.rs`). We also verify 
  variants of the permutation not currently used in SymCrypt. 
  
- **Parameter sets**: SHA3-224, SHA3-256, SHA3-384, SHA3-512,
  SHAKE128, SHAKE256. All six are verified simultaneously: the
  trait wrappers `Sha3State<R,B>` / `ShakeState<R,B>` are generic
  in the digest size `R` and rate `B`; per-algorithm instantiations
  are obtained by supplying the FIPS-202 `(R, B)` pair.

- **Verification**: Every entry point in §3 is verified against 
  FIPS 202 modulo the trust assumptions listed in §6. We also  
  verified an experimental 4-way data-parallel SIMD path 
  (`keccak4x.rs`, `keccak4x_hybrid.rs`, `shake4x.rs`). 
  
- **Out of scope** (not addressed by these proofs):
  - Performance, side-channel resistance, and constant-time properties.
  - Cryptographic security of FIPS 202 itself.
  - C FFI and interoperability.
    
---

## 2. From Rust to Lean — how the proofs are organised

Using the Rust → Charon → Aeneas → Lean pipeline, all SymCrypt-Rust code subject to
verification (for all algorithms including ML-KEM) is mechanically translated to Lean
definitions under `SymCRust/lean/Symcrust/Code/`. The translation of every Rust function is then equipped with an
`@[step]`-tagged theorem with precise pre- and post-conditions expressed using the Spec.

The file layout under `Properties/SHA3/` (LOC = `cloc` non-comment, non-blank source lines):

| Path | LOC | Contents |
|---|---:|---|
| `Basic.lean` | 245 | Shared auxiliary definitions and lemmas: `KeccakState`, `GhostState`, predicates (`absorbing`, `absorbingWeak`, `squeezing`, `squeezingStructural`, `spongeInvariant`), bridge primitives (`absorbBytes`, `padAndPermute`, `squeezeBytes`, `extractOutput`) |
| `Keccak/` | 2,071 | Keccak-f[1600] permutation: `θ`/`ρ`/`π`/`χ`/`ι` step functions (`Core.lean` 298), `#decompose`-folded round body (`Fold.lean` 88), the 24-round loop spec (`Loop.lean` 103), and the textbook permutation `keccak_permute_textbook.spec` that the sponge dispatches to (`Textbook.lean` 1,582) |
| `Keccak4x/` | 3,203 | 4-way data-parallel Keccak-f[1600]: lane state model (`State.lean` 669, `Lane4.lean` 408), the vectorised permutation (`Permute.lean` 316 with `Permute/Base.lean` 146, `Permute/Theta.lean` 275, `Permute/Chi.lean` 183), and the scalar-vs-SIMD hybrid equivalence (`Hybrid.lean` 635, `Hybrid/Phases.lean` 571) |
| `Sponge/` | 6,102 | Byte-level absorb/extract and the FIPS-202 bridge. `Init.lean` 63, `Padding.lean` 122, `Absorb.lean` 1,762, `Extract.lean` 2,064, plus a 4-way split of the spec bridge: `BridgeRepr.lean` 114 (representation), `BridgeBitFC.lean` 167 (bit-level FC), `BridgeComp.lean` 585 (composition), `BridgeMathFC.lean` 1,196 (math sublemmas), facade `Bridge.lean` 29 with the load-bearing `code_toSpec` |
| `Shake4x/` | 3,263 | 4-way data-parallel SHAKE: state basics (`Basic.lean` 136), incremental append (`Append.lean` 1,705), finalisation (`Finalize.lean` 375), extraction (`Extract.lean` 545), and the spec bridge (`Bridges.lean` 502) |
| `StatefulHash.lean` | 71 | Const-generic stateful hash `Sha3State<R,B>` + `OneShotSha3<R,B>` (SHA3-224/256/384/512) |
| `StatefulXof.lean` | 84 | Const-generic stateful XOF `ShakeState<R,B>` + `OneShotShake<R,B>` (SHAKE128/256) |
| `Variants.lean` | 151 | Legacy `shake1x.rs` incremental wrappers (`HXof`, `GXof`, `Sha3_256State`, `Sha3_512State`); verified but not integrated (§3.3) |
| **Total** | **15,217** | (incl. the 28-line aggregator `SHA3.lean`) |

---

## 3. Verified public API surface

The SHA-3 / SHAKE crate exposes three families of public types: a const-generic
stateful (incremental) hash and XOF interface (§3.1, §3.2), and a legacy
non-generic incremental interface inherited from `shake1x.rs` (§3.3). Each listed
entry has a corresponding `@[step]`-tagged Lean theorem. The "Standard reference"
column names the FIPS-202 spec function or byte equation the theorem discharges.
Lean theorem references use the form `name (file:line)`.

### 3.1. Const-generic stateful hash (SHA3-224/256/384/512)

The Rust types live in [`src/sha3/sha3_variants.rs`](../../../../src/sha3/sha3_variants.rs);
the Lean theorems all live in [`StatefulHash.lean`](./StatefulHash.lean).

| Rust function | Lean theorem | Standard reference (FIPS 202) |
|---|---|---|
| [`Sha3State::new`](../../../../src/sha3/sha3_variants.rs#L46) | [`Sha3State.new.spec`](./StatefulHash.lean#L47) | initialise sponge state to absorbing mode |
| [`Sha3State::append`](../../../../src/sha3/sha3_variants.rs#L55) | [`Sha3State.append.spec`](./StatefulHash.lean#L61) | absorb input bytes into the sponge |
| [`Sha3State::result`](../../../../src/sha3/sha3_variants.rs#L59) | [`Sha3State.result.spec`](./StatefulHash.lean#L80) | finalise and squeeze `R` bytes |
| [`OneShotSha3::hash`](../../../../src/sha3/sha3_variants.rs#L91) | [`OneShotSha3.hash.spec`](./StatefulHash.lean#L113) | `Spec.SHA3.sha3_{224,256,384,512}` (FIPS §6.1) |

The concrete `(R, B)` instantiations supplied at the type-alias
level in `sha3_variants.rs:80-83` and `sha3_variants.rs:102-105`
are: SHA3-224 `(28, 144)`, SHA3-256 `(32, 136)`, SHA3-384
`(48, 104)`, SHA3-512 `(64, 72)`. All four are discharged by the
*same* generic spec; the per-algorithm `h_rate` precondition
`0 < B ∧ 8·B < 1600 ∧ B mod 8 = 0` is closed by `native_decide`
at each call site.

### 3.2. Const-generic stateful XOF (SHAKE128, SHAKE256)

The Rust types live in [`src/sha3/shake_variants.rs`](../../../../src/sha3/shake_variants.rs);
the Lean theorems all live in [`StatefulXof.lean`](./StatefulXof.lean).

| Rust function | Lean theorem | Standard reference (FIPS 202) |
|---|---|---|
| [`ShakeState::new`](../../../../src/sha3/shake_variants.rs#L34) | [`ShakeState.new.spec`](./StatefulXof.lean#L42) | initialise sponge state to absorbing mode |
| [`ShakeState::append`](../../../../src/sha3/shake_variants.rs#L43) | [`ShakeState.append.spec`](./StatefulXof.lean#L56) | absorb input bytes into the sponge |
| [`ShakeState::extract`](../../../../src/sha3/shake_variants.rs#L47) | [`ShakeState.extract.spec`](./StatefulXof.lean#L71) | squeeze `output.length` bytes (variable-length) |
| [`ShakeState::result`](../../../../src/sha3/shake_variants.rs#L51) | [`ShakeState.result.spec`](./StatefulXof.lean#L91) | squeeze + wipe; fixed-length `R`-byte sibling of `extract` |
| [`OneShotShake::xof`](../../../../src/sha3/shake_variants.rs#L73) | [`OneShotShake.xof.spec`](./StatefulXof.lean#L118) | `Spec.SHA3.shake{128,256}` (FIPS §6.2) |

Instantiations: SHAKE128 `(R=32, B=168)`, SHAKE256 `(R=64, B=136)`.
The `R` parameter is only used by the convenience `result` /
`xof` methods (fixed-length output); `extract` is fully variable
length and is the load-bearing primitive for downstream consumers
that want streamed output (ML-KEM matrix sampling, ML-DSA CBD
sampling, …).

### 3.3. Legacy incremental wrappers (`shake1x.rs`)

`src/sha3/shake1x.rs` provides `HXof`, `GXof`, `Sha3_256State`, and
`Sha3_512State` — pre-const-generic incremental wrappers that predate
the API above. They are **not integrated** into SymCrypt's public
surface (they have no C ABI in `ffi.rs` and no production caller
consumes them), and will be retired. They are nonetheless verified,
end-to-end, in [`Variants.lean`](./Variants.lean): each spec composes
the same [`code_toSpec`](./Sponge/Bridge.lean#L55) bridge used for
§3.1/§3.2, so no new proof obligations arise.

### 3.4. Lower-level callable primitives

Beneath the trait wrappers above, the byte-level `KeccakState`
methods and the Keccak-f[1600] permutation itself are also each
equipped with `@[step]` specs and consumed by the higher-level
proofs. They are not part of the user-facing crate API (none are
`pub` outside the `sha3::*` module tree), but they appear in
proof citations throughout this document:

| Rust function | Lean theorem |
|---|---|
| [`keccak_permute`](../../../../src/sha3/sha3_impl.rs#L180) → [`keccak_permute_opt`](../../../../src/sha3/keccak_opt.rs#L23) | [`keccak_permute.spec`](./Keccak/Loop.lean#L157), [`keccak_permute_opt.spec`](./Keccak/Loop.lean#L136) |
| [`KeccakState::init`](../../../../src/sha3/sha3_impl.rs#L195) | [`Sponge/Init.lean`](./Sponge/Init.lean) |
| [`KeccakState::append_byte`](../../../../src/sha3/sha3_impl.rs) | [`KeccakState.append_byte.spec`](./Sponge/Absorb.lean#L316) |
| [`KeccakState::append_bytes`](../../../../src/sha3/sha3_impl.rs) | [`KeccakState.append_bytes.spec`](./Sponge/Absorb.lean#L454) |
| [`KeccakState::append_lanes`](../../../../src/sha3/sha3_impl.rs) | [`KeccakState.append_lanes.spec`](./Sponge/Absorb.lean#L869) |
| [`KeccakState::append`](../../../../src/sha3/sha3_impl.rs) | [`KeccakState.append.spec`](./Sponge/Absorb.lean#L1130) |
| [`KeccakState::extract`](../../../../src/sha3/sha3_impl.rs) | [`Sponge/Extract.lean`](./Sponge/Extract.lean) |

### 3.5. C ABI shims (`sha3/ffi.rs`)

The functions in `sha3/ffi.rs` that begin with `SymCryptSha3_*`
and `SymCryptShake*` are thin `#[no_mangle] extern "C"` shims
around the Rust functions above (e.g. `SymCryptSha3_256` unwraps
the C pointer/length pair and delegates to `OneShotSha3::<32, 136>::hash`).
The wrappers `{sha3,shake}_variants.rs` also still include 
unimplemented placeholders (`self_test`, `import_state`, `export_state`). 
Aeneas does not extract the FFI boundary, so verification
starts in the underlying Rust functions they 
delegate to, listed above. 
From the standpoint of FIPS-202 standards-compliance, every 
algorithmic obligation is discharged at the underlying Rust
function.

---

## 4. What each top-level proof guarantees

This section explains, for the entry points in §3, what their step
theorems actually assert. The const-generic hash and XOF families
have the same shape; we describe the hash family first and then
point out the XOF differences in §4.4.

### 4.0. Notations 

- **`KeccakState`** is the in-memory sponge state: 25 × `u64`
  lanes (the FIPS-202 1600-bit Keccak state), a byte cursor
  `state_index`, the cached rate `input_block_size`, the padding
  byte for the variant, and a `squeeze_mode` flag distinguishing
  absorb mode from squeeze mode. It is the Aeneas-extracted
  Rust type, threaded by every method through `&mut self`.

- **`GhostState`** ([`Basic.lean#L218`](./Basic.lean#L218)) is the
  proof-only twin of `KeccakState`: it records the *byte history*
  of the sponge (`absorbed : List U8`, `squeezed : List U8`) plus
  the rate / padding. A `GhostState` is never materialised at
  runtime; it is the spec-side handle the proof carries
  alongside the `KeccakState` so that every method's
  postcondition can talk about "the bytes the user has absorbed
  so far" without re-deriving them from the lane state.

- **`absorbing ks g`** / **`squeezing ks g`**
  ([`Basic.lean#L359`](./Basic.lean#L359),
  [`Basic.lean#L428`](./Basic.lean#L428)) are the two
  load-bearing invariants linking `ks : KeccakState` to
  `g : GhostState`. `absorbing` asserts that `ks` is mid-absorb
  on the byte history `g.absorbed` (with `g.squeezed = []`);
  `squeezing` asserts that `ks` has finished absorbing
  `g.absorbed` (padded and permuted) and has produced the
  prefix `g.squeezed` of output so far. Every method transports
  these invariants forward.

- **`extractOutput g outLen`** ([`Basic.lean#L440`](./Basic.lean#L440))
  is the spec-side function that says "given a ghost state `g`,
  what are the next `outLen` bytes of squeeze output?" It is the
  cleanest characterisation of `extract` / `result` at the
  bridge level.

- **Bridge-level vs FIPS-202.** The per-method specs in §3 land
  on the *bridge* vocabulary above (`absorbing`, `squeezing`,
  `extractOutput`) rather than directly on
  `Spec.SHA3.sha3_256` / `Spec.SHA3.shake128`. The bridge meets
  FIPS 202 in a single theorem, [`code_toSpec`](./Sponge/Bridge.lean#L55), which proves
  ```
  bytesToBits (squeezeBytes (padAndPermute (absorbBytes …)) …)
    = SPONGE KECCAK_f (8·rate) (bytesToBits msg ‖ suffix) (8·m)
  ```
  Every one-shot spec in §3.1 / §3.2 closes its FIPS-202 byte
  equation by composing its bridge-level post with `code_toSpec`.

### 4.1. The sponge state machine

A stateful sponge has two phases: **absorbing**, where input bytes
are mixed into the lane state, and **squeezing**, where output
bytes are extracted from it. Once squeezing begins, no further
input may be mixed into the *same* in-progress sponge: the
FIPS-202 padding boundary has been committed. The const-generic
wrappers nevertheless make it safe to call `append` after a
`result` / `extract`, because the implementation transparently
*resets* the sponge in that case. The runtime `squeeze_mode :
Bool` flag inside `KeccakState` carries the FSM phase, and the
proof picks the matching invariant:

| `squeeze_mode` | Invariant relating `ks` and `g` | Ghost history |
|---|---|---|
| `false` | `absorbing ks g` | `g.absorbed` = bytes consumed so far; `g.squeezed = []` |
| `true`  | `squeezing ks g` | `g.absorbed` = bytes committed to the squeeze; `g.squeezed` = output prefix emitted so far |

Public-API transitions (with `gInit := GhostState.init B padding`):

```
                      new
              ─────────────────►   absorbing  ks  gInit
                                       │
                          append data  │   (squeeze_mode = false branch)
                                       ▼
                                   absorbing  ks  g{absorbed ⧺= data}
                                       │
                              extract  │   (XOF only; pads + permutes once)
                                       ▼
                                   squeezing  ks  g{squeezed = out}
                                       │
                              extract  │   (XOF only; continues the squeeze)
                                       ▼
                                   squeezing  ks  g{squeezed ⧺= more}
                                       │
                                result │   (squeezes R bytes, then wipes;
                                       │    post-state is a fresh absorbing
                                       │    against gInit)
                                       ▼
                                   absorbing  ks  gInit
                                       │
                          append data2 │   (squeeze_mode = true branch:
                                       │    resets ghost history, then absorbs)
                                       ▼
                                   absorbing  ks  g{absorbed = data2}
```

Three properties make this FSM verification-friendly without
distorting the runtime API:

- **Ghost histories are erased at runtime.** `g.absorbed` /
  `g.squeezed` live only in the proof; the Rust state carries only
  the 25 lanes, the byte cursor `state_index`, the cached rate /
  padding, and `squeeze_mode`. Every method spec quantifies
  existentially over `g`, so a caller just threads the witness.

- **`squeeze_mode` selects the `append` branch.**
  `Sha3State.append` (and its XOF sibling) accepts the state in
  *either* `absorbing` or `squeezing` form and dispatches on
  `state.squeeze_mode`: if false, the new bytes extend the current
  absorb buffer; if true, the sponge is reset (lanes zeroed,
  cursor reset, flag cleared) and the new bytes begin a fresh
  absorb. This matches the SymCrypt C API contract that `append`
  after `result` is well-defined.

- **Hash vs. XOF only differ on `extract`.** `Sha3State` (hash
  family) exposes only `new` / `append` / `result`: there is no
  way to observe an in-progress squeeze — `result` finalises in
  one step and wipes. `ShakeState` (XOF family) additionally
  exposes `extract`, which is the only method whose post moves the
  FSM from `absorbing` to `squeezing` while leaving the state live
  for further calls. Both families share the absorb-side
  machinery and the same `extractOutput g outLen` characterisation
  of the bytes the sponge will emit from ghost state `g`.

### 4.2. `Sha3State` incremental methods

[`Sha3State.new.spec`](./StatefulHash.lean#L47) takes the rate
parameter `B` (with `h_rate`) and produces a fresh
`Sha3State R B` whose internal `KeccakState` is in
`absorbing` relation with the *initial* ghost state
`GhostState.init B SHA3_PADDING_VALUE h_rate` (empty absorbed
history, empty squeezed history, padding byte `0x06` as
prescribed by FIPS 202 §6.1).

[`Sha3State.append.spec`](./StatefulHash.lean#L61) takes the
current state `self` (in either `absorbing` or `squeezing`
relation with `g`) and a slice of input bytes `data`; on
return, the new state is in `absorbing` relation with
`g.append data.val self.state.squeeze_mode`. The `squeeze_mode`
disjunct lets the proof handle the FIPS-conformant pattern
where `append` after `result` *resets* the sponge to absorb
mode (rather than continuing the previous absorb). Arbitrary
input lengths are accepted — there is no alignment requirement
on `data.length`; the internal `KeccakState::append` handles
the head realignment (`append_bytes`) and tail (`append_byte`)
itself.

[`Sha3State.result.spec`](./StatefulHash.lean#L80) finalises
the sponge (pads + permutes) and squeezes exactly `R` bytes
into `output`; the post says
```
output.val = (extractOutput g R.val).toList
```
plus the post-state is `absorbing` against a fresh
ghost state (the implementation wipes the sponge on `result`).

### 4.3. `OneShotSha3.hash` — end-to-end FIPS-202 byte equation

[`OneShotSha3.hash.spec`](./StatefulHash.lean#L113) composes
`new`, `append`, and `result` into a single one-shot call,
with the bridge-level post
```
result.val = (extractOutput (gInit.append data.val false) R.val).toList
```
where `gInit := GhostState.init B SHA3_PADDING_VALUE h_rate`.
The FIPS-202 byte equation
```
result.val = (Spec.SHA3.sha3_R B (data.val) ).toList
```
follows by combining the above post with `code_toSpec`
specialised to `(rate = B, suffix = SHA3 hash suffix, m = R)`,
exactly as `Spec.SHA3.sha3_{224,256,384,512}` are defined at
[`Spec/SHA3/Spec.lean#L337-L340`](../../../../lean/Spec/SHA3/Spec.lean#L337).
The specialisation is monomorphic per concrete `(R, B)` pair.

### 4.4. `ShakeState` and `OneShotShake.xof`

The XOF family ([`StatefulXof.lean`](./StatefulXof.lean)) is the
exact analogue of the hash family with two differences. First,
the padding byte changes from `0x06` (SHA-3 hash suffix) to
`0x1F` (SHAKE XOF suffix); see the `SHAKE_PADDING_VALUE`
constant at [`shake_variants.rs#L10`](../../../../src/sha3/shake_variants.rs#L10).
Second, `extract` is fully variable length: it takes an
output slice of *any* size, and the post characterises the
output bytes via `extractOutput` of arbitrary length. This is
the load-bearing primitive for streamed XOF consumers (ML-KEM
matrix sampling, ML-DSA polynomial rejection sampling). The
FIPS-202 byte equation for `OneShotShake.xof` is obtained
the same way as in §4.3, this time landing on
`Spec.SHA3.shake{128,256}` (FIPS §6.2).

---

## 6. Trust footprint (axioms the proofs depend on)

This section lists every `axiom` declaration the verified
surface transitively depends on. There are **no SHA-3-specific
axioms**: the trust base is shared stdlib axioms plus Lean's
standard kernel axioms. 

We follow the README's five-category structure for the trust
footprint; categories with no applicable axiom are elided.

### 6.1. Operational primitives outside the Aeneas memory model

- **`Properties/Axioms/Wipe.lean :: common.wipe_slice.spec`**
  — `verify::common::wipe_slice<T>`.

## 7. Building and inspecting the proofs

The top-level [`README-VERIFIEDCRYPTO.md`](../../../../../README-VERIFIEDCRYPTO.md)
§4 documents the full build pipeline (C+Rust build, Rust tests,
Aeneas extraction, full Lean build). The commands below assume
that pipeline has been run at least once and the Aeneas-extracted
`Code/` is present.

```sh
cd SymCRust/lean

# Build the SHA-3 proofs only (incremental; seconds after a warm build).
lake build Symcrust.Properties.SHA3

# Spec-side sanity check (#guard examples + CAVP test vectors).
lake build Spec.SHA3

# List the axioms a given top-level proof depends on.
lake env lean -e '
  import Symcrust.Properties.SHA3
  open symcrust.sha3.sha3_variants
  open symcrust.sha3.shake_variants
  #print axioms OneShotSha3.hash.spec
  #print axioms OneShotShake.xof.spec
'
```

Each top-level theorem's `#print axioms` output corresponds to
the single category §6.1 (`common.wipe_slice.spec`) plus the
shared Aeneas-stdlib opaque axioms and `propext`,
`Classical.choice`, `Quot.sound` (Lean's standard kernel
axioms, shared with all of Mathlib).

---

## 8. References

- **NIST FIPS 202** — *SHA-3 Standard: Permutation-Based Hash
  and Extendable-Output Functions*, August 2015.
  Public URL: [NIST.FIPS.202.pdf](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
  (DOI [10.6028/NIST.FIPS.202](https://doi.org/10.6028/NIST.FIPS.202)).
- **NIST CAVP / ACVP** — short / long message and Monte Carlo
  test vectors for SHA3-{224,256,384,512} and SHAKE{128,256}.
  Replayed in `Spec/SHA3/TestVectors.lean`.
- **B. Barbosa et al., *The Keccak Reference***
  ([keccak.team](https://keccak.team/files/Keccak-reference-3.0.pdf))
  — the designers' specification, the source FIPS 202 is
  derived from. Useful when reading the round-constant /
  rotation-offset tables alongside the implementation.
