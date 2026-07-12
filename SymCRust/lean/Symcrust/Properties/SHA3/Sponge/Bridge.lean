import Symcrust.Properties.SHA3.Sponge.BridgeRepr
import Symcrust.Properties.SHA3.Sponge.BridgeBitFC
import Symcrust.Properties.SHA3.Sponge.BridgeComp
import Symcrust.Properties.SHA3.Sponge.BridgeMathFC

/-!
# SHA-3 Sponge Bridge — facade + math FC `code_toSpec`

Importing this file gives the full sponge bridge surface:

- `Sponge/BridgeRepr.lean` — representation lemmas + Nat helpers
  (`toBits_*`, `div_step`, `mod_step`, `toBits_byte_bit`,
  `byte_extract_bv`, `and7_val`, `and7_ne_zero_imp_lt`).
- `Sponge/BridgeBitFC.lean` — bit-level FC (`absorbByte_bridge`,
  `squeezeByte_toBits`, `keccak_permute_toBits`).
- `Sponge/BridgeComp.lean` — composition lemmas:
  `absorbBytesRaw_*`, `absorbBytes_*`, `squeezeAfter_*`, `squeezeBytes_*`,
  `extractOutput_*`, `GhostState.squeezeAdvance_*`,
  `List.setSlice!_setSlice!_append`.
- `Sponge/BridgeMathFC.lean` — math sublemmas:
  `absorbBytes_eq_SPONGE_absorb`, `padAndPermute_eq_final_block`,
  `squeezeBytes_eq_SPONGE_squeeze`.

This file additionally defines `code_toSpec`.
-/

namespace symcrust.sha3.sha3_impl

open Aeneas Aeneas.Std Spec
open Spec (𝔹 bytesToBits bitsToBytes Bits.toNatLE)
open Spec.SHA3 (b w KECCAK_f SPONGE «pad10*1» padLen padLen_dvd)
open scoped Spec.Notations
open scoped Spec.SHA3

open Spec.SHA3 (hashSuffix xofSuffix sha3_256 sha3_512 shake128 shake256)

/-! ### The core FC theorem: code-adjacent operations = FIPS 202 Spec

This theorem is the ONE place where we prove bridge = Spec. The RHS unfolds to
`sha3_256 msg` / `shake256 msg m` etc. for specific (rate, suffix, m) parameters. -/

/-- **The core FC theorem.** Both sides are `Vector Bool (8 * m)` (bit-strings).
    LHS: code-adjacent bridge functions applied to `msg`, lifted to bits.
    RHS: FIPS 202 `SPONGE` applied to `bytesU8ToBits msg ‖ suffix`.

    Note: `SPONGE` internally applies `pad10*1`; we only have to thread the
    domain-separation `suffix` between the message bits and the padding.

    Composition of:
    - `absorbBytes_eq_SPONGE_absorb` (BridgeMathFC.lean): byte absorb +
      padAndPermute = SPONGE.absorb of (bytesToBits msg ‖ suffix ‖ pad10*1).
    - `squeezeBytes_eq_SPONGE_squeeze` (BridgeMathFC.lean): byte squeeze =
      bitsToBytes ∘ SPONGE.squeeze.
    - `bytesToBits_bitsToBytes` round-trip to lift to bits on both sides. -/
theorem code_toSpec {n s} (msg : Vector U8 n) (suffix : Vector Bool s)
    (rate m : Nat) (hs : s + 1 ≤ 8) (hsmall : s + 1 < 8)
    (hr : 0 < rate ∧ 8 * rate < b) :
    let (S, idx) := absorbBytes (Vector.replicate b false) 0 rate msg.toList
    let S' := padAndPermute S idx rate (encodePadVal suffix hs)
    bytesU8ToBits (squeezeBytes S' 0 rate m) =
      SPONGE KECCAK_f (8 * rate) (bytesU8ToBits msg ‖ suffix) (8 * m) := by
  -- Destructure the absorb result so we can rewrite freely.
  generalize hAbs : absorbBytes (Vector.replicate b false) 0 rate msg.toList = absResult
  obtain ⟨S, idx⟩ := absResult
  show bytesU8ToBits (squeezeBytes (padAndPermute S idx rate (encodePadVal suffix hs)) 0 rate m) =
       SPONGE KECCAK_f (8 * rate) (bytesU8ToBits msg ‖ suffix) (8 * m)
  -- Step 1: byte-squeeze (lifted to bits) = SPONGE.squeeze
  rw [squeezeBytes_eq_SPONGE_squeeze _ rate m hr]
  -- Step 2: padAndPermute (post-absorb-state) = SPONGE.absorb of padded message
  have hsorb := absorbBytes_eq_SPONGE_absorb msg suffix rate hs hsmall hr
  rw [hAbs] at hsorb
  rw [hsorb]
  -- Step 3: SPONGE unfolds to SPONGE.squeeze ∘ SPONGE.absorb
  unfold SPONGE
  rfl

end symcrust.sha3.sha3_impl
