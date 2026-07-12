/-
  # Encoding/RoundTrip.lean — blob round-trip for `key_set_value` ∘ `key_get_value`.

  Top-level **blob round-trip** properties of ML-KEM key serialization:

  > Loading a blob `b` of format `F` with `key_set_value(b, F)` into a
  > fresh key container `k`, then writing it back out with
  > `key_get_value(k, F)`, recovers `b` (modulo `Slice.toSpec`).

  Each format gets its own theorem (`PrivateSeed`, `EncapsulationKey`,
  `DecapsulationKey`), since `key_set_value` exposes its FC postcondition
  in format-specific shapes.  All three discharge against
  `mlkem.key_get_value.spec`'s already-bundled `Key.toSpec`
  postcondition (`KeyGetValue.lean:957`).

  The proofs operate *equationally* (no Hoare-triple composition):
  given equational hypotheses about the two calls returning `NoError`,
  unfold each spec's Hoare triple to its postcondition via
  `WP.spec_ok_pair`, then chain `pb_src.toSpec = k.toSpec = pb_dst'.toSpec`.

  See `KeySetValue.lean` for the loader, `KeyGetValue.lean` for the
  writer, and `KeySetValue/Prelude.lean` for `Key.toSpec`,
  `wfKeyFormat`, and `slice_toSpec_eq_concat2`.
-/
import Symcrust.Properties.MLKEM.Encoding.KeySetValue
import Symcrust.Properties.MLKEM.Encoding.KeyGetValue

open Aeneas Aeneas.Std Result
open Spec
open Spec.MLKEM
open symcrust
open symcrust.common

namespace Symcrust.Properties.MLKEM

open Symcrust.Properties.MLKEM.Bridges

/-! ## Helper: `Key.toSpec` equality on the PrivateSeed arm

`key_set_value` on the `PrivateSeed` arm exposes
`private_seed.toSpec = pb_src.toSpecWindow 0 32 …` and
`private_random.toSpec = pb_src.toSpecWindow 32 32 …`.  Unfolding
`Key.toSpec_PrivateSeed` and gluing the two windows via
`slice_toSpec_eq_concat2` yields the bundled
`Key.toSpec .PrivateSeed`-form equality consumed by the round-trip. -/

private theorem ksv_PrivateSeed_toSpec_eq
    {params : ParameterSet}
    (key' : mlkem.key.Key) (pb_src : Slice U8)
    (h_len : pb_src.length = 64)
    (h_seed : key'.private_seed.toSpec =
              pb_src.toSpecWindow 0 32 (by simp [h_len]))
    (h_rand : key'.private_random.toSpec =
              pb_src.toSpecWindow 32 32 (by simp [h_len])) :
    key'.toSpec mlkem.key.Format.PrivateSeed params =
      pb_src.toSpec _ (by simp [mlkem.key.Format.length, h_len]) := by
  rw [Key.toSpec_PrivateSeed, h_seed, h_rand]
  have hcat := slice_toSpec_eq_concat2 (m := 32) (n := 32) pb_src
    (by simpa using h_len) (by simp [h_len]) (by simp [h_len])
  change (pb_src.toSpecWindow 0 32 (by simp [h_len]) ++
      pb_src.toSpecWindow 32 32 (by simp [h_len])) =
    pb_src.toSpec 64 (by simp [h_len])
  simpa using hcat.symm

/-! ## PrivateSeed round-trip

Loading a 64-byte `d ‖ z` blob, then writing it back, recovers the
input blob bytewise. -/

/-- **Round-trip for the `PrivateSeed` format**.

Equational form: given any two successful calls
`key_set_value` then `key_get_value` (both with NoError outcome on the
PrivateSeed arm), the output blob `pb_dst'` viewed as a 64-byte spec
equals the input blob `pb_src` viewed as a 64-byte spec. -/
theorem mlkem.key_value_roundtrip_PrivateSeed
    {params : ParameterSet} (flags1 flags2 : U32)
    (pb_src : Slice U8) (h_src_len : pb_src.length = 64)
    (pk_mlkem_key : mlkem.key.Key) (h_wf : wfKey pk_mlkem_key params)
    (pb_dst : Slice U8)
    {k1 : mlkem.key.Key} {pb_dst' : Slice U8}
    (h_ksv : mlkem.key_set_value pb_src mlkem.key.Format.PrivateSeed
              flags1 pk_mlkem_key = ok (common.Error.NoError, k1))
    (h_kgv : mlkem.key_get_value k1 pb_dst mlkem.key.Format.PrivateSeed
              flags2 = ok (common.Error.NoError, pb_dst')) :
    ∃ h : pb_dst'.length = 64,
      pb_dst'.toSpec _ h = pb_src.toSpec _ h_src_len := by
  -- Extract `key_set_value`'s post at the concrete return value.
  have h_ksv_post := mlkem.key_set_value.spec (params := params)
    pb_src mlkem.key.Format.PrivateSeed flags1 pk_mlkem_key h_wf
  rw [h_ksv] at h_ksv_post
  simp only at h_ksv_post
  obtain ⟨_h_wfKey_k1, _h_params, _h_n_rows, h_arm⟩ := h_ksv_post
  -- h_arm : (match .NoError ...) reduces to PrivateSeed arm body.
  simp only at h_arm
  obtain ⟨h_len64, h_seed, h_rand, _h_pseed_flag, _h_pkey_flag, h_wfps⟩ := h_arm
  -- Build `wfKeyFormat k1 .PrivateSeed params`.
  have h_wfKF : wfKeyFormat k1 mlkem.key.Format.PrivateSeed params := h_wfps
  -- Extract `key_get_value`'s post at the concrete return value.
  have h_kgv_post := mlkem.key_get_value.spec (params := params)
    k1 pb_dst mlkem.key.Format.PrivateSeed flags2 h_wfKF
  rw [h_kgv] at h_kgv_post
  simp only at h_kgv_post
  obtain ⟨_h_dst_len_eq, h_kgv_arm⟩ := h_kgv_post
  simp only at h_kgv_arm
  obtain ⟨h_dst_len, h_toSpec_kgv⟩ := h_kgv_arm
  -- Build `k1.toSpec .PrivateSeed = pb_src.toSpec` from ksv.
  have h_toSpec_ksv :=
    ksv_PrivateSeed_toSpec_eq (params := params) k1 pb_src h_len64 h_seed h_rand
  -- Compose via transitivity.  Both sides equal `k1.toSpec ... = `; flip kgv.
  have h_chain : pb_dst'.toSpec _ h_dst_len = pb_src.toSpec _ h_src_len := by
    rw [← h_toSpec_kgv, h_toSpec_ksv]
  exact ⟨by simpa [mlkem.key.Format.length] using h_dst_len, h_chain⟩

/-! ## EncapsulationKey round-trip

`key_set_value` on the `EncapsulationKey` arm already exposes the
bundled `encapsulationKey k1 params = pb_src.toSpec _ h_len`
equation (KeySetValue.lean:241).  Unfolding `Key.toSpec_EncapsulationKey`
identifies the LHS with `k1.toSpec .EncapsulationKey params`. -/

/-- **Round-trip for the `EncapsulationKey` format**.

Equational form mirroring the PrivateSeed variant: a successful
load-then-store pair recovers the original blob bytewise. -/
theorem mlkem.key_value_roundtrip_EncapsulationKey
    {params : ParameterSet} (flags1 flags2 : U32)
    (pb_src : Slice U8) (h_src_len : pb_src.length = 384 * (k params : ℕ) + 32)
    (pk_mlkem_key : mlkem.key.Key) (h_wf : wfKey pk_mlkem_key params)
    (pb_dst : Slice U8)
    {k1 : mlkem.key.Key} {pb_dst' : Slice U8}
    (h_ksv : mlkem.key_set_value pb_src mlkem.key.Format.EncapsulationKey
              flags1 pk_mlkem_key = ok (common.Error.NoError, k1))
    (h_kgv : mlkem.key_get_value k1 pb_dst mlkem.key.Format.EncapsulationKey
              flags2 = ok (common.Error.NoError, pb_dst')) :
    ∃ h : pb_dst'.length = 384 * (k params : ℕ) + 32,
      pb_dst'.toSpec _ h = pb_src.toSpec _ h_src_len := by
  have h_ksv_post := mlkem.key_set_value.spec (params := params)
    pb_src mlkem.key.Format.EncapsulationKey flags1 pk_mlkem_key h_wf
  rw [h_ksv] at h_ksv_post
  simp only at h_ksv_post
  obtain ⟨_h_wfKey_k1, _h_params, _h_n_rows, h_arm⟩ := h_ksv_post
  obtain ⟨h_len_ek, _h_ekT, _h_pub_seed, _h_hash, _h_pseed_flag, _h_pkey_flag,
          h_wfek, h_bundled⟩ := h_arm
  -- `wfEncapKey k1 params` IS `wfKeyFormat k1 .EncapsulationKey params`.
  have h_wfKF : wfKeyFormat k1 mlkem.key.Format.EncapsulationKey params := h_wfek
  have h_kgv_post := mlkem.key_get_value.spec (params := params)
    k1 pb_dst mlkem.key.Format.EncapsulationKey flags2 h_wfKF
  rw [h_kgv] at h_kgv_post
  simp only at h_kgv_post
  obtain ⟨_h_dst_len_eq, h_kgv_arm⟩ := h_kgv_post
  obtain ⟨h_dst_len, h_toSpec_kgv⟩ := h_kgv_arm
  -- `Key.toSpec_EncapsulationKey` unfolds `k1.toSpec .EncapsulationKey params`
  -- to `encapsulationKey k1 params`.  The bundled ksv equation then provides
  -- `encapsulationKey k1 params = pb_src.toSpec _ h_len_ek`.
  rw [Key.toSpec_EncapsulationKey] at h_toSpec_kgv
  have h_chain : pb_dst'.toSpec _ h_dst_len = pb_src.toSpec _ h_src_len := by
    rw [← h_toSpec_kgv, h_bundled]
  exact ⟨by simpa [mlkem.key.Format.length] using h_dst_len, h_chain⟩

/-! ## DecapsulationKey round-trip

Loading a `768·k + 96`-byte `dkPKE ‖ ek ‖ H(ek) ‖ z` blob, then writing it
back, recovers the input blob bytewise.  The `dkPKE`/s-prefix equality
(`keySEncoded key' = pb_src[0..384·k]`) is the canonical 12-bit
`ByteEncode∘ByteDecode` round-trip now exposed by `key_set_value.spec`;
gluing the five windows via `mlkem.ksv_decapsulationKey_toSpec_eq` yields the
bundled `decapsulationKey key' params = pb_src.toSpec _` consumed here. -/

/-- **Round-trip for the `DecapsulationKey` format**.

Equational form mirroring the `PrivateSeed` / `EncapsulationKey` variants: a
successful load-then-store pair recovers the original blob bytewise. -/
theorem mlkem.key_value_roundtrip_DecapsulationKey
    {params : ParameterSet} (flags1 flags2 : U32)
    (pb_src : Slice U8) (h_src_len : pb_src.length = 768 * (k params : ℕ) + 96)
    (pk_mlkem_key : mlkem.key.Key) (h_wf : wfKey pk_mlkem_key params)
    (pb_dst : Slice U8)
    {k1 : mlkem.key.Key} {pb_dst' : Slice U8}
    (h_ksv : mlkem.key_set_value pb_src mlkem.key.Format.DecapsulationKey
              flags1 pk_mlkem_key = ok (common.Error.NoError, k1))
    (h_kgv : mlkem.key_get_value k1 pb_dst mlkem.key.Format.DecapsulationKey
              flags2 = ok (common.Error.NoError, pb_dst')) :
    ∃ h : pb_dst'.length = 768 * (k params : ℕ) + 96,
      pb_dst'.toSpec _ h = pb_src.toSpec _ h_src_len := by
  have h_ksv_post := mlkem.key_set_value.spec (params := params)
    pb_src mlkem.key.Format.DecapsulationKey flags1 pk_mlkem_key h_wf
  rw [h_ksv] at h_ksv_post
  simp only at h_ksv_post
  obtain ⟨_h_wfKey_k1, _h_params, _h_n_rows, h_arm⟩ := h_ksv_post
  obtain ⟨h_len, h_s, h_t, h_pub, h_hash, _h_sha, h_rand, _h_pseed_flag,
          _h_pkey_flag, h_wfdk⟩ := h_arm
  -- `wfDecapKey k1 params` IS `wfKeyFormat k1 .DecapsulationKey params`.
  have h_wfKF : wfKeyFormat k1 mlkem.key.Format.DecapsulationKey params := h_wfdk
  have h_kgv_post := mlkem.key_get_value.spec (params := params)
    k1 pb_dst mlkem.key.Format.DecapsulationKey flags2 h_wfKF
  rw [h_kgv] at h_kgv_post
  simp only at h_kgv_post
  obtain ⟨_h_dst_len_eq, h_kgv_arm⟩ := h_kgv_post
  obtain ⟨h_dst_len, h_toSpec_kgv⟩ := h_kgv_arm
  -- `Key.toSpec_DecapsulationKey` unfolds `k1.toSpec .DecapsulationKey params`
  -- to `decapsulationKey k1 params`.  The assembly helper then provides
  -- `decapsulationKey k1 params = pb_src.toSpec _ h_len`.
  rw [Key.toSpec_DecapsulationKey] at h_toSpec_kgv
  have h_toSpec_ksv :=
    mlkem.ksv_decapsulationKey_toSpec_eq k1 pb_src h_len h_s h_t h_pub h_hash h_rand
  have h_chain : pb_dst'.toSpec _ h_dst_len = pb_src.toSpec _ h_src_len := by
    rw [← h_toSpec_kgv, h_toSpec_ksv]
  exact ⟨by simpa [mlkem.key.Format.length] using h_dst_len, h_chain⟩

end Symcrust.Properties.MLKEM
