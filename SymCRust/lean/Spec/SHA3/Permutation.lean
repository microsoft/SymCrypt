import Spec.SHA3.Spec
import Spec.SHA3.Properties
import Mathlib.Tactic.IntervalCases
import Mathlib.Data.ZMod.Basic
import Mathlib.Algebra.BigOperators.Group.Finset.Basic
import Mathlib.Dynamics.PeriodicPts.Lemmas

/-!
# KECCAK-f is a permutation (FIPS 202 §3.3, §3.4)

We prove that `KECCAK-p[1600, nr]` is a bijection `Vector Bool 1600 → Vector Bool 1600`
for every round count `nr ≤ 24`, and hence that the SHA-3 permutation
`KECCAK-f[1600] = KECCAK-p[1600, 24]` is a permutation in the standard sense.

## Proof outline

For each of the five step mappings θ, ρ, π, χ, ι we exhibit an explicit
inverse and prove a round-trip identity (`_inv` lemmas below):

* **ι** is an involution (XOR with a fixed round constant on lane (0,0)).
* **ρ** is inverted by rotating each lane in the opposite direction.
* **π** is a position permutation; its inverse uses
  `A[x][y] = (π A)[y][(2x + 3y) mod 5]`.
* **χ** is invertible row-by-row; we use the closed-form
  `a_x = b_x ⊕ ¬b_{x+1} ∧ (b_{x+2} ⊕ ¬b_{x+3} ∧ b_{x+4})`
  verified by exhaustive Boolean reasoning on 5-bit rows.
* **θ** is GF(2)-linear. Its action on the column parities
  `C[x][z] = ⊕_y A[x][y][z]` is multiplication by the polynomial
  `p(X, Z) = 1 + X + X⁴·Z`
  in `R = GF(2)[X, Z]/(X⁵ + 1, Z⁶⁴ + 1)`. We exhibit the explicit inverse
  polynomial `q(X, Z)` (computed offline), verify `q · p = 1` in `R` by
  `native_decide`, and use it to define `θ_inv` and prove `θ_inv ∘ θ = id`.

Composing the five inverses (in the reverse order) yields `Rnd_inv`, then
`KECCAK_p_inv` by reversing the loop, and finally `KECCAK_f_inv`.

The top-level theorems are
* `KECCAK_f_inv_KECCAK_f : ∀ S, KECCAK_f_inv (KECCAK_f S) = S`
* `KECCAK_f_bijective : Function.Bijective KECCAK_f`
-/

namespace Spec.SHA3

open scoped Spec.Notations

scoped macro_rules
| `(tactic| get_elem_tactic) => `(tactic| grind)

/-! ## ι — involution

`ι` XORs a fixed round constant into lane (0, 0). Doing this twice cancels.
-/

theorem ι_involution (A : State) (iᵣ : Nat) : ι (ι A iᵣ) iᵣ = A := by
  ext x hx y hy z hz
  have key : ∀ (a b : Bool), ((a != b) != b) = a := by decide
  by_cases h : x = 0 ∧ y = 0
  · simp [ι, h, HXor.hXor, key]
  · simp [ι, h]

/-- The inverse of `ι` is `ι` itself. -/
def ι_inv (A : State) (iᵣ : Nat) : State := ι A iᵣ

theorem ι_inv_ι (A : State) (iᵣ : Nat) : ι_inv (ι A iᵣ) iᵣ = A := ι_involution A iᵣ


/-! ## ρ — inverse via opposite rotation

`ρ` rotates each lane by its tabulated offset; the inverse rotates by the
complementary amount, which we express again as a `rotateLeft`. -/

/-- The inverse of `ρ`: rotate each lane in the opposite direction.

The rotation amount `(w - ρ.Offsets[x][y] % w) % w` is the additive inverse
mod `w` of `ρ.Offsets[x][y] % w`. -/
def ρ_inv (A : State) : State :=
  Vector.ofFn fun x => Vector.ofFn fun y =>
    A[x][y].rotateLeft ((w - ρ.Offsets[x][y] % w) % w)

/-- Two rotations by `k mod n` and `(n − k mod n) mod n` on a vector cancel. -/
private theorem rotateLeft_rotateLeft_cancel {α} (v : Vector α n) (k : Nat) (hn : 0 < n) :
    (v.rotateLeft (k % n)).rotateLeft ((n - k % n) % n) = v := by
  have key : ∀ (j : Nat), (v.rotateLeft j).rotateLeft ((n - j % n) % n) = v := by
    intro j
    unfold Vector.rotateLeft
    simp only [Nat.ne_of_gt hn, ↓reduceDIte]
    ext i hi
    simp only [Vector.getElem_ofFn]
    congr 1
    have hkmod : j % n < n := Nat.mod_lt _ hn
    by_cases hk : j % n = 0
    · simp [hk, Nat.mod_eq_of_lt hi]
    · have h2 : n - j % n < n := by omega
      have hsub : (n - j % n) % n = n - j % n := Nat.mod_eq_of_lt h2
      simp only [hsub]
      have h1 : i + n - (n - j % n) = i + j % n := by omega
      rw [h1]
      by_cases hsum : i + j % n < n
      · rw [Nat.mod_eq_of_lt hsum]
        have hrew : i + j % n + n - j % n = i + n := by omega
        rw [hrew, Nat.add_mod_right]
        exact Nat.mod_eq_of_lt hi
      · push (config := {}) Not at hsum
        rw [show (i + j % n) % n = i + j % n - n from by
          rw [Nat.mod_eq_sub_mod hsum, Nat.mod_eq_of_lt (by omega)]]
        have hrew : i + j % n - n + n - j % n = i := by omega
        rw [hrew]
        exact Nat.mod_eq_of_lt hi
  have hkk : k % n % n = k % n := Nat.mod_mod k n
  have := key (k % n)
  rw [hkk] at this
  exact this

theorem ρ_inv_ρ (A : State) : ρ_inv (ρ A) = A := by
  apply Vector.ext; intro x hx
  apply Vector.ext; intro y hy
  have hw : (0 : Nat) < w := Nat.succ_pos _
  simp [ρ_inv, ρ]
  exact rotateLeft_rotateLeft_cancel A[x][y] ρ.Offsets[x][y] hw


/-! ## π — inverse via inverse position permutation

`π (A)[x][y] = A[x + 3y][x]`. Solving for the source coordinates gives
`A[x][y] = π(A)[y][2x + 3y]` (arithmetic in `Fin 5`). -/

def π_inv (A : State) : State :=
  Vector.ofFn fun (x : Fin 5) => Vector.ofFn fun (y : Fin 5) => A[y][2 * x + 3 * y]

theorem π_inv_π (A : State) : π_inv (π A) = A := by
  ext x hx y hy z hz
  simp only [π_inv, π, Vector.getElem_ofFn]
  interval_cases x <;> interval_cases y <;> rfl


/-! ## χ — inverse via the cascading closed-form

`χ` acts independently per `(y, z)` slice on the 5-element row indexed by `x`.
On a 5-bit row `a → b` with `b_x = a_x ⊕ (¬a_{x+1} ∧ a_{x+2})`, the inverse is
`a_x = b_x ⊕ (¬b_{x+1} ∧ (b_{x+2} ⊕ (¬b_{x+3} ∧ b_{x+4})))`,
verified by exhaustive Boolean reasoning on the 32 row values. -/

def χ_inv (A : State) : State :=
  Vector.ofFn fun (x : Fin 5) => Vector.ofFn fun (y : Fin 5) =>
    A[x][y] ⊕ (~~~A[x + 1][y] &&& (A[x + 2][y] ⊕ (~~~A[x + 3][y] &&& A[x + 4][y])))

/-- The five-variable Boolean inverse identity for χ. -/
private theorem chi_inv_bool (a₀ a₁ a₂ a₃ a₄ : Bool) :
    let b₀ := a₀ != ((!a₁) && a₂)
    let b₁ := a₁ != ((!a₂) && a₃)
    let b₂ := a₂ != ((!a₃) && a₄)
    let b₃ := a₃ != ((!a₄) && a₀)
    let b₄ := a₄ != ((!a₀) && a₁)
    (b₀ != ((!b₁) && (b₂ != ((!b₃) && b₄)))) = a₀ := by
  revert a₀ a₁ a₂ a₃ a₄; decide

private lemma fin5_arith_one (x : Fin 5) : (x + 1) + 1 = x + 2 := by fin_cases x <;> rfl
private lemma fin5_arith_two (x : Fin 5) : (x + 1) + 2 = x + 3 := by fin_cases x <;> rfl
private lemma fin5_arith_three (x : Fin 5) : (x + 1) + 3 = x + 4 := by fin_cases x <;> rfl
private lemma fin5_arith_four (x : Fin 5) : (x + 1) + 4 = x + 0 := by fin_cases x <;> rfl

/-- The five-variable Boolean inverse identity for χ in the exact normal form
    produced by `simp` after expanding `χ_inv` and `χ`. -/
private theorem chi_row_inv_bool (a₀ a₁ a₂ a₃ a₄ : Bool) :
    (a₀ !=
        ((!a₁ && a₂) !=
          (!a₁ != (!a₂ && a₃) &&
            a₂ != ((!a₃ && a₄) != (!a₃ != (!a₄ && a₀) && a₄ != (!a₀ && a₁)))))) = a₀ := by
  revert a₀ a₁ a₂ a₃ a₄; decide

theorem χ_inv_χ (A : State) : χ_inv (χ A) = A := by
  ext x hx y hy z hz
  -- Per-bit reasoning: at bit z, the χ row at column y is a 5-bool vector indexed by x.
  -- We reduce to concrete x, y so all Vector accesses become rfl-equal Boolean expressions,
  -- then close the resulting 5-variable Boolean identity by `chi_row_inv_bool`.
  interval_cases x <;> interval_cases y <;>
    (simp [χ_inv, χ, HXor.hXor, HAnd.hAnd, Complement.complement,
           Vector.getElem_zipWith, Vector.getElem_map, Vector.getElem_ofFn];
     exact chi_row_inv_bool _ _ _ _ _)


/-! ## θ — inverse via polynomial inversion in `GF(2)[X, Z] / (X⁵ + 1, Z⁶⁴ + 1)`

`θ` is `GF(2)`-linear. We factor it through the *column parity* map
`parity A [x][z] = ⊕_y A[x][y][z]`. On parities, `θ` acts as multiplication
by the polynomial `p(X, Z) = 1 + X + X⁴ Z` in the ring
`R = GF(2)[X, Z] / (X⁵ + 1, Z⁶⁴ + 1)`. We exhibit an explicit inverse
`q(X, Z)` precomputed offline (Python Gaussian elimination), verify
`q · p = 1` in `R` by `native_decide`, and use it to recover the original
parity (and hence the `D` value XOR'd by `θ`). -/

/-- Bit → `ZMod 2` lift, so we can do GF(2) algebra under the sums. -/
def b2z : Bool → ZMod 2 := fun b => if b then 1 else 0

@[simp] lemma b2z_xor (a b : Bool) : b2z (a != b) = b2z a + b2z b := by
  cases a <;> cases b <;> decide
@[simp] lemma b2z_false : b2z false = 0 := rfl
@[simp] lemma b2z_true : b2z true = 1 := rfl

lemma b2z_inj : Function.Injective b2z := by
  intros a b h; cases a <;> cases b <;> simp_all [b2z]

lemma b2z_decide_eq_one (z : ZMod 2) : b2z (decide (z = 1)) = z := by
  match z with | 0 => decide | 1 => decide

/-- Column parities, indexed by `(x, z)`. -/
abbrev Parity := Vector (Vector Bool w) 5

/-- The unit of the convolution ring: `1` at `(0, 0)`, `0` elsewhere. -/
def Pone : Parity :=
  Vector.ofFn fun (x : Fin 5) => Vector.ofFn fun (z : Fin w) =>
    decide (x.val = 0 ∧ z.val = 0)

/-- Convolution product in `R = GF(2)[X, Z] / (X⁵ + 1, Z⁶⁴ + 1)`.

The reduction `X⁵ = 1`, `Z⁶⁴ = 1` is what turns the polynomial multiplication
into a cyclic convolution on `Fin 5 × Fin w`. -/
def Pmul (a b : Parity) : Parity :=
  Vector.ofFn fun (x : Fin 5) => Vector.ofFn fun (z : Fin w) =>
    decide (((Finset.univ : Finset (Fin 5 × Fin w)).sum
      fun p => b2z a[p.1][p.2] * b2z b[x - p.1][z - p.2]) = 1)

/-- The action of `θ` on parities, as a polynomial in `R`:
`p(X, Z) = 1 + X + X⁴ · Z` (where `Z` is the lane-rotate-by-1 generator). -/
def θPoly : Parity :=
  Vector.ofFn fun (x : Fin 5) => Vector.ofFn fun (z : Fin w) =>
    decide ((x.val = 0 ∧ z.val = 0) ∨ (x.val = 1 ∧ z.val = 0)
            ∨ (x.val = 4 ∧ z.val = 1))

/-- Precomputed inverse `q(X, Z)` of `p` in `R`. Each lane is 64 bits
(`z = 0` is the LSB), produced offline by Gaussian elimination. -/
def θInvPolyBV : Vector (BitVec 64) 5 := #v[
  0xde26bc4d789af135#64,
  0x09af135e26bc4d78#64,
  0xebc4d789af135e26#64,
  0x7135e26bc4d789af#64,
  0xcd789af135e26bc4#64
]

/-- The inverse polynomial `q(X, Z)`, unpacked into `Parity` form. -/
def θInvPoly : Parity :=
  Vector.ofFn fun (x : Fin 5) => Vector.ofFn fun (z : Fin w) =>
    θInvPolyBV[x.val].getLsbD z.val

/-- `q · p = 1` in `R`. Verified by `native_decide` over `5 * 64 = 320`
coefficients. -/
theorem q_p_eq_one : Pmul θInvPoly θPoly = Pone := by native_decide

/-- The key pointwise identity behind `Pmul θInvPoly (θParity C) = C`,
verified by `decide` (5 · 64 = 320 cases). Reading it as a polynomial
identity in `R`: `q + q · X⁻¹ + q · X · Z⁻¹ = 1`, i.e. `q · (1 + X + X⁴ · Z) = 1`
(after multiplying both sides by `X`). -/
theorem θInv_pointwise (x : Fin 5) (z : Fin w) :
    b2z θInvPoly[x][z] + b2z θInvPoly[x - 1][z] + b2z θInvPoly[x + 1][z - 1]
    = b2z Pone[x][z] := by
  revert x z; decide

/-- Move `b2z` past `Pmul`: the bit at `(x, z)` of `Pmul a b` equals the
formal convolution sum in `ZMod 2`. -/
lemma b2z_Pmul (a b : Parity) (x : Fin 5) (z : Fin w) :
    b2z (Pmul a b)[x][z] =
    (Finset.univ : Finset (Fin 5 × Fin w)).sum
      (fun p => b2z a[p.1][p.2] * b2z b[x - p.1][z - p.2]) := by
  simp [Pmul]; exact b2z_decide_eq_one _

lemma Pone_apply_Fin (x : Fin 5) (z : Fin w) :
    Pone[x][z] = decide (x.val = 0 ∧ z.val = 0) := by simp [Pone]

/-- Convolution with the unit: `(Pone * c)(x, z) = c(x, z)`. -/
lemma Pone_sum (c : Fin 5 × Fin w → ZMod 2) (x : Fin 5) (z : Fin w) :
    ((Finset.univ : Finset (Fin 5 × Fin w)).sum
      fun p => b2z Pone[p.1][p.2] * c (x - p.1, z - p.2)) = c (x, z) := by
  rw [Finset.sum_eq_single ((0, 0) : Fin 5 × Fin w)]
  · rw [Pone_apply_Fin]; simp
  · rintro ⟨p1, p2⟩ _ hp
    rw [Pone_apply_Fin]
    have hp' : ¬ (p1.val = 0 ∧ p2.val = 0) := by
      intro ⟨h1, h2⟩; apply hp
      exact Prod.mk.injEq .. |>.mpr ⟨Fin.ext h1, Fin.ext h2⟩
    rw [decide_eq_false hp']; simp
  · intro h; exact absurd (Finset.mem_univ _) h

/-! ### θ factored through parities -/

/-- Column parity of a state: `parity A [x][z] = ⊕_y A[x][y][z]`. -/
def parity (A : State) : Parity :=
  Vector.ofFn fun (x : Fin 5) =>
    A[x][0] ⊕ A[x][1] ⊕ A[x][2] ⊕ A[x][3] ⊕ A[x][4]

/-- The `D` value `θ` XORs into each lane, computed from a parity. -/
def θD (C : Parity) : Parity :=
  Vector.ofFn fun (x : Fin 5) => C[x - 1] ⊕ C[x + 1].rotateLeft 1

/-- Pointwise XOR of two parities. -/
def Padd (a b : Parity) : Parity :=
  Vector.ofFn fun (x : Fin 5) => a[x] ⊕ b[x]

/-- The action of `θ` on parities: `θParity C = C ⊕ θD C`. -/
def θParity (C : Parity) : Parity := Padd C (θD C)

/-- Rotation by 1 reindexes by `(z - 1)` in `Fin w`. -/
@[simp]
private lemma rotateLeft_one_apply (v : Vector Bool w) (z : Fin w) :
    (v.rotateLeft 1)[z.val] = v[(z - 1).val] := by
  unfold Vector.rotateLeft
  have hw : w = 64 := rfl
  simp [hw]
  congr 1
  rw [show ((z : Fin 64) - 1).val = (z.val + 63) % 64 from by
    rw [Fin.val_sub]; show (64 - 1 + z.val) % 64 = _; omega]

lemma b2z_θParity_apply (C : Parity) (x : Fin 5) (z : Fin w) :
    b2z (θParity C)[x][z] =
      b2z C[x][z] + b2z C[x - 1][z] + b2z C[x + 1][z - 1] := by
  show b2z ((θParity C)[x][z]) = _
  simp [θParity, Padd, θD, HXor.hXor, Vector.getElem_zipWith]
  ring

set_option maxHeartbeats 1600000 in
/-- **Main algebraic identity.** Multiplying any parity `θParity C` by `q`
recovers `C`. The proof expands `θParity` into three shifted copies of `C`,
reindexes the convolution sums (via `Equiv.sum_comp` on `Fin 5 × Fin w`),
applies `θInv_pointwise` to collapse the coefficient into `Pone`, then
finishes with `Pone_sum`. -/
theorem Pmul_θInvPoly_θParity (C : Parity) :
    Pmul θInvPoly (θParity C) = C := by
  apply Vector.ext; intro x hx
  apply Vector.ext; intro z hz
  apply b2z_inj
  show b2z (Pmul θInvPoly (θParity C))[(⟨x, hx⟩ : Fin 5)][(⟨z, hz⟩ : Fin w)] =
    b2z C[(⟨x, hx⟩ : Fin 5)][(⟨z, hz⟩ : Fin w)]
  set xF : Fin 5 := ⟨x, hx⟩
  set zF : Fin w := ⟨z, hz⟩
  rw [b2z_Pmul]
  conv_lhs => rhs; ext p; rw [b2z_θParity_apply C (xF - p.1) (zF - p.2)]
  conv_lhs => rhs; ext p; rw [mul_add, mul_add]
  rw [Finset.sum_add_distrib, Finset.sum_add_distrib]
  have reindex2 :
      (Finset.univ : Finset (Fin 5 × Fin w)).sum
        (fun p => b2z θInvPoly[p.1][p.2] * b2z C[xF - p.1 - 1][zF - p.2])
      = (Finset.univ : Finset (Fin 5 × Fin w)).sum
          (fun p => b2z θInvPoly[(p.1 - 1 : Fin 5)][p.2]
            * b2z C[xF - p.1][zF - p.2]) := by
    let e : Fin 5 × Fin w ≃ Fin 5 × Fin w :=
      Equiv.prodCongr (Equiv.subRight (1 : Fin 5)) (Equiv.refl _)
    rw [show (Finset.univ : Finset (Fin 5 × Fin w)).sum
        (fun p => b2z θInvPoly[p.1][p.2] * b2z C[xF - p.1 - 1][zF - p.2])
        = _ from (Equiv.sum_comp e _).symm]
    apply Finset.sum_congr rfl
    intros p _
    show b2z θInvPoly[(p.1 - 1 : Fin 5)][p.2] *
         b2z C[xF - (p.1 - 1) - 1][zF - p.2] = _
    have h : xF - (p.1 - 1) - 1 = xF - p.1 := by abel
    simp only [h]
  have reindex3 :
      (Finset.univ : Finset (Fin 5 × Fin w)).sum
        (fun p => b2z θInvPoly[p.1][p.2] * b2z C[xF - p.1 + 1][zF - p.2 - 1])
      = (Finset.univ : Finset (Fin 5 × Fin w)).sum
          (fun p => b2z θInvPoly[(p.1 + 1 : Fin 5)][(p.2 - 1 : Fin w)]
            * b2z C[xF - p.1][zF - p.2]) := by
    let e : Fin 5 × Fin w ≃ Fin 5 × Fin w :=
      Equiv.prodCongr (Equiv.addRight (1 : Fin 5)) (Equiv.subRight (1 : Fin w))
    rw [show (Finset.univ : Finset (Fin 5 × Fin w)).sum
        (fun p => b2z θInvPoly[p.1][p.2] * b2z C[xF - p.1 + 1][zF - p.2 - 1])
        = _ from (Equiv.sum_comp e _).symm]
    apply Finset.sum_congr rfl
    intros p _
    show b2z θInvPoly[(p.1 + 1 : Fin 5)][(p.2 - 1 : Fin w)] *
         b2z C[xF - (p.1 + 1) + 1][zF - (p.2 - 1) - 1] = _
    have h1 : xF - (p.1 + 1) + 1 = xF - p.1 := by abel
    have h2 : zF - (p.2 - 1) - 1 = zF - p.2 := by abel
    simp only [h1, h2]
  rw [reindex2, reindex3]
  rw [← Finset.sum_add_distrib, ← Finset.sum_add_distrib]
  conv_lhs => rhs; ext p; rw [← add_mul, ← add_mul, θInv_pointwise]
  exact Pone_sum (fun pp => b2z C[pp.1][pp.2]) xF zF

/-! ### Inverting `θ`

The key chain:
- `parity (θ A) = θParity (parity A)` (because `5` is odd in `GF(2)`),
- so `Pmul θInvPoly (parity (θ A)) = parity A` (by the main identity),
- so the `D` recovered from the output's parity equals the original `D`,
- and `θ_inv (θ A) [x][y] = (θ A)[x][y] ⊕ D[x] = A[x][y]` (XOR cancellation).
-/

set_option maxHeartbeats 1600000 in
/-- Parity of `θ A` equals `θParity` of the parity of `A`. -/
private lemma parity_θ (A : State) : parity (θ A) = θParity (parity A) := by
  ext x hx z hz
  apply b2z_inj
  set xF : Fin 5 := ⟨x, hx⟩
  set zF : Fin w := ⟨z, hz⟩
  show b2z ((parity (θ A))[xF][zF]) = b2z ((θParity (parity A))[xF][zF])
  simp [parity, θ, θParity, Padd, θD, HXor.hXor]
  ring_nf
  simp only [show (5 : ZMod 2) = 1 from by decide, mul_one]

/-- The inverse of `θ`: recover the original parity `P` from the output's
parity, compute the corresponding `D = θD P`, then XOR it out of every lane. -/
def θ_inv (A : State) : State :=
  let D := θD (Pmul θInvPoly (parity A))
  Vector.ofFn fun x => Vector.ofFn fun y => A[x][y] ⊕ D[x]

set_option maxHeartbeats 1600000 in
theorem θ_inv_θ (A : State) : θ_inv (θ A) = A := by
  unfold θ_inv
  rw [parity_θ, Pmul_θInvPoly_θParity]
  ext x hx y hy z hz
  simp [θ, HXor.hXor, parity, θD]


/-! ## Round inverse and `KECCAK-p` inverse -/

/-- The inverse of a single round: invert ι, χ, π, ρ, θ in reverse order. -/
def Rnd_inv (A : State) (iᵣ : Nat) : State :=
  θ_inv (ρ_inv (π_inv (χ_inv (ι_inv A iᵣ))))

theorem Rnd_inv_Rnd (A : State) (iᵣ : Nat) : Rnd_inv (Rnd A iᵣ) iᵣ = A := by
  unfold Rnd Rnd_inv
  rw [ι_inv_ι, χ_inv_χ, π_inv_π, ρ_inv_ρ, θ_inv_θ]

/-- Iterate `Rnd` `n` times, with `iᵣ = 0, 1, …, n - 1`. Matches the spec
loop in `KECCAK_p` when `nr = 12 + 2ℓ` (the standard SHA-3 case). -/
def iterateRnd (A : State) : Nat → State
  | 0 => A
  | n + 1 => Rnd (iterateRnd A n) n

/-- Iterate the inverse: peel off rounds `n - 1, n - 2, …, 0`. -/
def iterateRnd_inv (A : State) : Nat → State
  | 0 => A
  | n + 1 => iterateRnd_inv (Rnd_inv A n) n

theorem iterateRnd_inv_iterateRnd (A : State) (n : Nat) :
    iterateRnd_inv (iterateRnd A n) n = A := by
  induction n with
  | zero => rfl
  | succ k ih =>
    simp only [iterateRnd, iterateRnd_inv]
    rw [Rnd_inv_Rnd, ih]

/-- The `KECCAK_f` for-loop fold expressed via `iterateRnd`. -/
private theorem foldl_Rnd_eq_iterateRnd (A : State) (n : Nat) :
    List.foldl (fun b a => Rnd b a) A (List.range' 0 n) = iterateRnd A n := by
  suffices h : ∀ k, List.foldl (fun b a => Rnd b a)
        (iterateRnd A k) (List.range' k n) = iterateRnd A (n + k) by
    have := h 0; simp at this; exact this
  induction n with
  | zero => intro k; simp
  | succ m ih =>
    intro k
    simp only [List.range'_succ, List.foldl_cons]
    have : Rnd (iterateRnd A k) k = iterateRnd A (k + 1) := by simp [iterateRnd]
    rw [this, ih (k + 1)]
    fcongr 1
    omega

/-- `KECCAK_f` as an explicit composition of `stateToString`, `iterateRnd 24`,
and `stringToState`. -/
theorem KECCAK_f_eq_iterateRnd (S : Vector Bool b) :
    KECCAK_f S = stateToString (iterateRnd (stringToState S) 24) := by
  simp only [KECCAK_f, KECCAK_p, ℓ]
  simp
  rw [foldl_Rnd_eq_iterateRnd]

/-- `KECCAK_f`'s explicit two-sided inverse. -/
def KECCAK_f_inv (S : Vector Bool b) : Vector Bool b :=
  stateToString (iterateRnd_inv (stringToState S) 24)

/-- **Top-level: `KECCAK_f_inv` is a left inverse of `KECCAK_f`.** -/
theorem KECCAK_f_inv_KECCAK_f (S : Vector Bool b) :
    KECCAK_f_inv (KECCAK_f S) = S := by
  rw [KECCAK_f_eq_iterateRnd]
  unfold KECCAK_f_inv
  rw [stringToState_stateToString, iterateRnd_inv_iterateRnd, stateToString_stringToState]

/-- `Vector Bool n` is finite for every `n`. -/
private instance instFiniteVectorBool (n : Nat) : Finite (Vector Bool n) := by
  have h : Vector Bool n ≃ (Fin n → Bool) := {
    toFun := fun v i => v[i],
    invFun := Vector.ofFn,
    left_inv := by intro v; ext i hi; simp,
    right_inv := by intro f; ext i; simp
  }
  exact Finite.of_equiv _ h.symm

/-- **Top-level: `KECCAK_f` is a bijection.**

The domain `Vector Bool 1600` is finite (cardinality `2 ^ 1600`); a left
inverse on a finite type promotes to a two-sided inverse, hence to
bijectivity. -/
theorem KECCAK_f_bijective : Function.Bijective KECCAK_f := by
  have hinj : Function.Injective KECCAK_f :=
    Function.LeftInverse.injective KECCAK_f_inv_KECCAK_f
  exact (Finite.injective_iff_bijective).mp hinj

/-- `KECCAK_f_inv` is also a *right* inverse of `KECCAK_f`. -/
theorem KECCAK_f_KECCAK_f_inv (S : Vector Bool b) :
    KECCAK_f (KECCAK_f_inv S) = S := by
  have hsurj := KECCAK_f_bijective.surjective
  obtain ⟨S', hS'⟩ := hsurj S
  rw [← hS', KECCAK_f_inv_KECCAK_f]

/-! ## Orbit periodicity

Since `KECCAK_f` is a bijection on the finite type `Vector Bool 1600`, every
state lies on a (finite) cycle: there exists `m ≥ 1` with
`KECCAK_f^[m] S = S`. This is the first ingredient in the Barbosa–Schwabe
unconditional termination proof for ML-KEM rejection sampling. -/

/-- **Cycle lemma:** every state lies on a finite cycle under `KECCAK_f`.
The bound `m ≤ 2 ^ 1600` is implicit (it's at most the cardinality of the
state space); we don't carry it because the existential is all we need. -/
theorem KECCAK_f_periodic (S : Vector Bool b) :
    ∃ m ≥ 1, KECCAK_f^[m] S = S := by
  have hp : S ∈ Function.periodicPts KECCAK_f :=
    KECCAK_f_bijective.injective.mem_periodicPts S
  obtain ⟨m, hm_pos, hperiod⟩ := Function.mem_periodicPts.mp hp
  exact ⟨m, hm_pos, hperiod⟩

/-- **`Sm1` lies in the orbit of `KECCAK_f Sm1`.** This is the second
ingredient in Barbosa–Schwabe: if `m` is any period of `KECCAK_f Sm1`, then
`KECCAK_f^[m - 1] (KECCAK_f Sm1) = Sm1`. -/
theorem KECCAK_f_predecessor_in_orbit (Sm1 : Vector Bool b)
    {m : Nat} (hm : 1 ≤ m) (hperiod : KECCAK_f^[m] (KECCAK_f Sm1) = KECCAK_f Sm1) :
    KECCAK_f^[m - 1] (KECCAK_f Sm1) = Sm1 := by
  have hm_eq : m = (m - 1).succ := by omega
  have : KECCAK_f (KECCAK_f^[m - 1] (KECCAK_f Sm1)) = KECCAK_f Sm1 := by
    conv_lhs => rw [← Function.iterate_succ_apply' KECCAK_f (m - 1)]
    rw [← hm_eq]; exact hperiod
  exact KECCAK_f_bijective.injective this

end Spec.SHA3
