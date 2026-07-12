/-
  ML-KEM parameter-set bridge — sub-file of `Properties/MLKEM/Basic`.

  Carries the `ParameterSet` ↔ `mlkem.key.Params` conversion,
  `wfInternalParams` and its per-field projection lemmas, the
  `cipherlength` / `lengthInvalidArg` length helpers, the
  `MLWE_POLYNOMIAL_COEFFICIENTS_val` scalar, the
  `mlkem_M_lt_A` constant inequality, and the
  `mlkem.key.Params.ne.spec` step axiom.

  Imports no Mathlib — keep it that way so consumers that only need
  parameter metadata don't pay the ZMod load cost.
-/
import Symcrust.Code
import Spec.MLKEM.Spec
import Symcrust.Properties.MLKEM.AeneasExtras
import Symcrust.Properties.Axioms.Stdlib

open Aeneas Aeneas.Std Result
open scoped Spec.Notations

namespace Symcrust.Properties.MLKEM

open Spec
open Spec.MLKEM
open Spec.MLKEM.Bounds
open symcrust

/-! ## Parameter-set numeric bounds

Closed-form bounds used as side conditions in `Bridges/KeyView` and other
files indexing into the fixed-size data buffer.

These are registered as `@[grind →]` so that `grind` (and the
`get_elem_tactic := grind` autoparam used for `a[i]` accesses) can
discharge bounds like `i.val * (k p) + col < 24` automatically from
`i.val < k p ∧ col < k p` without callers needing explicit `'(by ...)`
proofs. -/

@[grind .]
theorem k_le_4 (p : ParameterSet) : (k p : ℕ) ≤ 4 := by cases p <;> decide

@[grind .]
theorem k_ge_2 (p : ParameterSet) : 2 ≤ (k p : ℕ) := by cases p <;> decide

@[grind .]
theorem k_sq_plus_2k_le_24 (p : ParameterSet) :
    (k p : ℕ) * (k p : ℕ) + 2 * (k p : ℕ) ≤ 24 := by cases p <;> decide

/-! ## Constant inequalities used by the MulAccum / MatVec specs

`M = 3328·3328 = 11,075,584` (max squared coefficient product) and
`A = 3494·3254 = 11,369,476` (max `MontReduce(a₁·b₁) · ζ` product)
appear in the strict-`c1` accumulator bound.
The slack `A − M = 293,892` is exactly what makes the tight-odd
invariant `pa_tmp[2j+1] ≤ K·2·M` strictly less than the loose uniform
bound `K·(M+A)`; this lemma is the keystone of the tight odd-position
invariant.

Registered as `@[scalar_tac_simps]` so `scalar_tac` can close
the strict-`c1` discharge `K·2·M < 3·(M+A)` (for `K ≤ 3`) without
manual `decide` invocation at the use site. -/
@[scalar_tac_simps]
theorem mlkem_M_lt_A : (3328 : ℕ) * 3328 < 3494 * 3254 := by decide

/-! ## Parameter sets -/

/-- Spec ↦ Rust enum mapping. Used as an inverse to `paramsToSpec` in
`wfInternalParams`. -/
@[reducible]
def specToRustParams : ParameterSet → mlkem.key.Params
  | .ML_KEM_512  => .MlKem512
  | .ML_KEM_768  => .MlKem768
  | .ML_KEM_1024 => .MlKem1024

/-- Rust ↦ spec enum mapping. Used in every postcondition that constrains
a parametric Rust function in spec terms. -/
@[reducible]
def paramsToSpec : mlkem.key.Params → ParameterSet
  | .MlKem512  => .ML_KEM_512
  | .MlKem768  => .ML_KEM_768
  | .MlKem1024 => .ML_KEM_1024

@[simp] theorem paramsToSpec_specToRustParams (p : ParameterSet) :
    paramsToSpec (specToRustParams p) = p := by cases p <;> rfl

@[simp] theorem specToRustParams_paramsToSpec (p : mlkem.key.Params) :
    specToRustParams (paramsToSpec p) = p := by cases p <;> rfl

/-- `wfInternalParams ip p` says the cached `InternalParams` struct `ip`
agrees with the canonical table entry for spec parameter set `p`. From
this single invariant every numeric field of `ip` simplifies to its spec
value. -/
def wfInternalParams (ip : mlkem.key.InternalParams) (p : ParameterSet) : Prop :=
  ip = match p with
       | .ML_KEM_512  => mlkem.key.INTERNAL_PARAMS_MLKEM512
       | .ML_KEM_768  => mlkem.key.INTERNAL_PARAMS_MLKEM768
       | .ML_KEM_1024 => mlkem.key.INTERNAL_PARAMS_MLKEM1024

/-! ### Per-field projection lemmas

These collapse a `wfInternalParams ip p` hypothesis into concrete numeric
facts about the cached fields, rewriting in spec terms (`k`, `η₁`, `η₂`,
`dᵤ`, `dᵥ`). -/
namespace wfInternalParams

variable {ip : mlkem.key.InternalParams} {p : ParameterSet}

@[simp] theorem params_eq (h : wfInternalParams ip p) :
    ip.params = specToRustParams p := by
  cases p <;> (unfold wfInternalParams at h; simp [h,
    mlkem.key.INTERNAL_PARAMS_MLKEM512, mlkem.key.INTERNAL_PARAMS_MLKEM768,
    mlkem.key.INTERNAL_PARAMS_MLKEM1024, specToRustParams])

@[simp] theorem n_rows_val (h : wfInternalParams ip p) :
    ip.n_rows.val = (k p : ℕ) := by
  cases p <;> (unfold wfInternalParams at h; simp [h,
    mlkem.key.INTERNAL_PARAMS_MLKEM512, mlkem.key.INTERNAL_PARAMS_MLKEM768,
    mlkem.key.INTERNAL_PARAMS_MLKEM1024])

@[simp] theorem n_eta1_val (h : wfInternalParams ip p) :
    ip.n_eta1.val = (η₁ p : ℕ) := by
  cases p <;> (unfold wfInternalParams at h; simp [h,
    mlkem.key.INTERNAL_PARAMS_MLKEM512, mlkem.key.INTERNAL_PARAMS_MLKEM768,
    mlkem.key.INTERNAL_PARAMS_MLKEM1024])

@[simp] theorem n_eta2_val (h : wfInternalParams ip p) :
    ip.n_eta2.val = (η₂ : ℕ) := by
  cases p <;> (unfold wfInternalParams at h; simp [h,
    mlkem.key.INTERNAL_PARAMS_MLKEM512, mlkem.key.INTERNAL_PARAMS_MLKEM768,
    mlkem.key.INTERNAL_PARAMS_MLKEM1024, η₂])

@[simp] theorem n_bits_of_u_val (h : wfInternalParams ip p) :
    ip.n_bits_of_u.val = dᵤ p := by
  cases p <;> (unfold wfInternalParams at h; simp [h,
    mlkem.key.INTERNAL_PARAMS_MLKEM512, mlkem.key.INTERNAL_PARAMS_MLKEM768,
    mlkem.key.INTERNAL_PARAMS_MLKEM1024, dᵤ])

@[simp] theorem n_bits_of_v_val (h : wfInternalParams ip p) :
    ip.n_bits_of_v.val = dᵥ p := by
  cases p <;> (unfold wfInternalParams at h; simp [h,
    mlkem.key.INTERNAL_PARAMS_MLKEM512, mlkem.key.INTERNAL_PARAMS_MLKEM768,
    mlkem.key.INTERNAL_PARAMS_MLKEM1024, dᵥ])

/-- Bundle of all six per-field projections.  One `obtain` extracts the
full numeric profile of `ip` in a single line, replacing the
five-to-six-`have`-block boilerplate that appears at the top of every
encaps/decaps/key spec body. -/
theorem fieldVals (h : wfInternalParams ip p) :
    ip.params = specToRustParams p ∧
    ip.n_rows.val = (k p : ℕ) ∧
    ip.n_eta1.val = (η₁ p : ℕ) ∧
    ip.n_eta2.val = (η₂ : ℕ) ∧
    ip.n_bits_of_u.val = dᵤ p ∧
    ip.n_bits_of_v.val = dᵥ p :=
  ⟨params_eq h, n_rows_val h, n_eta1_val h, n_eta2_val h,
   n_bits_of_u_val h, n_bits_of_v_val h⟩

end wfInternalParams

/-! ## ML-KEM ciphertext byte length

`cipherlength p = 32 · (dᵤ p · k p + dᵥ p)` matches FIPS 203 §6.2 (the
total byte size of `c = c₁ ‖ c₂` where `c₁` encodes `Compress_dᵤ(u)`
over `k` polynomials and `c₂` encodes `Compress_dᵥ(v)` over one
polynomial).  Used as the `pb_ciphertext.length` precondition on every
encapsulate/decapsulate top-level spec. -/
@[reducible, scalar_tac_simps]
def cipherlength (params : ParameterSet) : ℕ :=
  32 * (dᵤ params * (k params : ℕ) + dᵥ params)

/-! ## `InvalidArgument` predicate shared by every encapsulate/decapsulate top-level spec

`lengthInvalidArg params pb_agreed_secret pb_ciphertext` is the disjunctive
length-mismatch predicate triggered on every `Error.InvalidArgument` arm of
`mlkem.encapsulate{_internal,_ex,}.spec` and `mlkem.decapsulate.spec`
(mlkem.rs:608 for Encaps, mlkem.rs:792 for Decaps).  Factored here so the
four specs share a single source of truth — strengthen once, propagate
everywhere.

Marked as `abbrev` so `step*` and the `case h1` discharge see through
to the underlying `_ ∨ _` shape without an explicit `unfold` — `left` /
`right` work transparently. -/
abbrev lengthInvalidArg (params : ParameterSet)
    (pb_agreed_secret pb_ciphertext : Slice U8) : Prop :=
  pb_agreed_secret.length ≠ 32 ∨ pb_ciphertext.length ≠ cipherlength params

/-! ## ML-KEM serialised-key byte length per `Format`

`Format.length f p` gives the byte length of a serialised ML-KEM key in
format `f`, parameter set `p`:

* `PrivateSeed`      : 64
* `EncapsulationKey` : 384·k + 32
* `DecapsulationKey` : 768·k + 96 = 2·(384·k) + 3·32

This matches the runtime helper `mlkem.sizeof_key_format_from_params`
(`Ffi.lean:155`).  Used as the `pb_{src,dst}.length` precondition /
InvalidArgument disjunct on `key_{set,get}_value.spec`. -/
@[reducible, scalar_tac_simps]
def _root_.symcrust.mlkem.key.Format.length
    (self : mlkem.key.Format) (params : ParameterSet) : ℕ :=
  match self with
  | .PrivateSeed       => 64
  | .EncapsulationKey  => 384 * (k params : ℕ) + 32
  | .DecapsulationKey  => 768 * (k params : ℕ) + 96

/-! ## MLWE_POLYNOMIAL_COEFFICIENTS scalar lemma

`mlkem.key.MLWE_POLYNOMIAL_COEFFICIENTS = 256#usize` is `@[global_simps,
irreducible]` in `Code/Funs.lean`. Register the `_val` lemma so every
solver can use the concrete value. See `aeneas-lean-core`, "Extracted
Rust constants are irreducible". -/
@[simp, scalar_tac_simps, agrind =, grind =, bvify]
theorem MLWE_POLYNOMIAL_COEFFICIENTS_val :
    mlkem.key.MLWE_POLYNOMIAL_COEFFICIENTS.val = 256 := by
  unfold mlkem.key.MLWE_POLYNOMIAL_COEFFICIENTS; rfl

/-! ## Generic `Inhabited` instance for `Std.Array α n`

Parameterized over `α` and `n` — a specialized instance like
`Inhabited (Array U16 256#usize)` triggers an elaboration bug at every
`getElem!` site (see the analogous comment in
`Properties/MLDSA/Basic.lean`). -/
instance (α : Type) [Inhabited α] (n : Usize) : Inhabited (Array α n) :=
  ⟨Array.repeat n default⟩

/-! ## Stdlib boolean: `Error PartialEq.ne`

The generic `common.Error.ne.spec` axiom (plus `DecidableEq` for
`symcrust.common.Error`) lives in `Properties/Axioms/Stdlib.lean`. -/

-- `mlkem.key.Params` is auto-generated without a `DecidableEq` instance;
-- declare one here so we can state the spec via `decide (p1 ≠ p2)`.
deriving instance DecidableEq for mlkem.key.Params

/-- **Step spec for `mlkem.key.{PartialEq for Params}::eq`**.

The extracted `eq` compares discriminants; for the flat `Params` enum this is
structural equality. This `@[step]` spec lets `step` chain through the generic
`PartialEq.ne.trait_default` spec (which needs the `eq` behaviour) at the
`Params` instance — e.g. for the `params != …` gates in
`mlkem.sizeof_ciphertext_from_params`. -/
@[step]
theorem mlkem.key.Params.eq.step.spec (p1 p2 : mlkem.key.Params) :
    mlkem.key.Params.Insts.CoreCmpPartialEqParams.eq p1 p2
    ⦃ (b : Bool) => b ↔ (p1 = p2) ⦄ := by
  unfold mlkem.key.Params.Insts.CoreCmpPartialEqParams.eq
  simp only [WP.spec_ok, decide_eq_true_eq]
  constructor
  · intro h; cases p1 <;> cases p2 <;> simp_all [mlkem.key.Params.read_discriminant]
  · intro h; subst h; rfl

/-- **Step spec for `Params::ne`** as seen in extracted code
(`PartialEq.ne.trait_default` at the `Params` instance): returns
`decide (p1 ≠ p2)`. Unconditional (proved from the generic
`ne.trait_default` spec + `Params.eq`), so `step` applies it directly. -/
@[step]
theorem mlkem.key.Params.ne.trait_default.spec (p1 p2 : mlkem.key.Params) :
    Aeneas.Std.core.cmp.PartialEq.ne.trait_default
      mlkem.key.Params.Insts.CoreCmpPartialEqParams p1 p2
    ⦃ (b : Bool) => b = decide (p1 ≠ p2) ⦄ := by
  apply WP.spec_mono
    (Aeneas.Std.core.cmp.PartialEq.ne.trait_default.spec
      mlkem.key.Params.Insts.CoreCmpPartialEqParams p1 p2
      (mlkem.key.Params.eq.step.spec p1 p2))
  intro b hb
  cases b <;> simp_all

end Symcrust.Properties.MLKEM
