import Symcrust.Properties.SHA3.Basic

/-!
# Keccak-f[1600] Core — Pure Permutation Algebra on Lanes25

Defines the five Keccak permutations (θ, ρ, π, χ, ι) as pure functions on
`Lanes25` and proves each matches the FIPS 202 spec via `toState` bridge.

## Contents

- `toLane` simp lemmas (XOR, AND, NOT, rotate)
- `Fin5x5_cases` for 25-way case splits
- Per-permutation: definition (`xxxCore`), per-lane lemma (`xxxCore_get`),
  spec bridge (`xxxCore_toState`)
- `fusedCore` = χ∘π∘ρ∘θ composed, `fusedRoundCore` adds ι
- `iterateRndCore` iterates 24 rounds, `iterateRndCore_toState` bridges to spec
-/

namespace symcrust

open Aeneas Aeneas.Std Result
open Spec
open Spec.SHA3 (w)
open sha3.sha3_impl
open scoped Spec.SHA3
open scoped Spec.Notations

/- Fast default for array bound goals: discharge with `scalar_tac`. -/
local macro_rules | `(tactic| get_elem_tactic) => `(tactic| scalar_tac)

private abbrev rot := core.num.U64.rotate_left

/-! ## Simp infrastructure -/

/-- Congruence under `Vector.ofFn`. -/
theorem Vector.ofFn_congr {n : Nat} {α : Type u} {f g : Fin n → α}
    (h : ∀ i, f i = g i) : Vector.ofFn f = Vector.ofFn g :=
  congrArg Vector.ofFn (funext h)

@[simp] theorem toLane_xor (a b : U64) : toLane (a ^^^ b) = toLane a ^^^ toLane b := by
  show _ = Vector.zipWith (· != ·) (toLane a) (toLane b)
  apply Vector.ext; intro i hi
  simp only [toLane, Vector.getElem_ofFn, Vector.getElem_zipWith]
  change (a.bv ^^^ b.bv).getLsbD i = _
  rw [BitVec.getLsbD_xor]

@[simp] theorem toLane_and (a b : U64) : toLane (a &&& b) = toLane a &&& toLane b := by
  show _ = Vector.zipWith (· && ·) (toLane a) (toLane b)
  apply Vector.ext; intro i hi
  simp only [toLane, Vector.getElem_ofFn, Vector.getElem_zipWith]
  change (a.bv &&& b.bv).getLsbD i = _
  rw [BitVec.getLsbD_and]

@[simp] theorem toLane_not (a : U64) : toLane (~~~a) = ~~~(toLane a) := by
  show _ = Vector.map (!·) (toLane a)
  apply Vector.ext; intro i hi
  simp only [toLane, Vector.getElem_ofFn, Vector.getElem_map]
  change (~~~a.bv).getLsbD i = _
  rw [BitVec.getLsbD_not]
  simp [show i < 64 from hi]

theorem toLane_rotate (a : U64) (k : U32) :
    toLane (core.num.U64.rotate_left a k) = (toLane a).rotateLeft k.bv.toNat := by
  apply Vector.ext; intro i hi
  simp only [toLane, Vector.rotateLeft, show w ≠ 0 from by omega,
             ↓reduceDIte, Vector.getElem_ofFn,
             core.num.U64.rotate_left, UScalar.rotate_left]
  change (a.bv.rotateLeft k.bv.toNat).getLsbD i = _
  rw [BitVec.getLsbD_rotateLeft]
  simp only [Bool.cond_decide, show w = 64 from rfl]
  set n := k.bv.toNat % 64
  have hn : n < 64 := Nat.mod_lt _ (by omega)
  split
  · congr 1; omega
  · rename_i hge
    have hi64 : i < 64 := hi
    simp only [hi64, decide_true, Bool.true_and]
    congr 1; omega

@[simp] private theorem rot_zero (x : U64) : core.num.U64.rotate_left x 0#u32 = x := by
  unfold core.num.U64.rotate_left UScalar.rotate_left; ext; simp

@[simp] private theorem Lane_xor_assoc (a b c : SHA3.Lane) :
    a ^^^ b ^^^ c = a ^^^ (b ^^^ c) := by
  apply Vector.ext; intro i hi
  show (a ^^^ b ^^^ c)[i] = (a ^^^ (b ^^^ c))[i]
  simp only [HXor.hXor, Vector.getElem_zipWith]
  cases a[i] <;> cases b[i] <;> cases c[i] <;> rfl

@[simp] private theorem u32_one_toNat : (U32.bv 1#u32).toNat = 1 := rfl

/-- Case-split on all 25 (x, y) pairs for x y : Fin 5. -/
theorem Fin5x5_cases {P : Fin 5 → Fin 5 → Prop}
    (h00 : P 0 0) (h10 : P 1 0) (h20 : P 2 0) (h30 : P 3 0) (h40 : P 4 0)
    (h01 : P 0 1) (h11 : P 1 1) (h21 : P 2 1) (h31 : P 3 1) (h41 : P 4 1)
    (h02 : P 0 2) (h12 : P 1 2) (h22 : P 2 2) (h32 : P 3 2) (h42 : P 4 2)
    (h03 : P 0 3) (h13 : P 1 3) (h23 : P 2 3) (h33 : P 3 3) (h43 : P 4 3)
    (h04 : P 0 4) (h14 : P 1 4) (h24 : P 2 4) (h34 : P 3 4) (h44 : P 4 4)
    : ∀ x y, P x y := by
  intro x y
  obtain ⟨_ | _ | _ | _ | _ | _, hx⟩ := x <;>
    (first | omega | (obtain ⟨_ | _ | _ | _ | _ | _, hy⟩ := y <;> first | omega | assumption))

/-! ## Core permutation steps (Lanes25 → Lanes25) -/

/-- θ core: column parity + diffusion. -/
def thetaCore (s : Lanes25) : Lanes25 :=
  let c0 := s.l0 ^^^ s.l5 ^^^ s.l10 ^^^ s.l15 ^^^ s.l20
  let c1 := s.l1 ^^^ s.l6 ^^^ s.l11 ^^^ s.l16 ^^^ s.l21
  let c2 := s.l2 ^^^ s.l7 ^^^ s.l12 ^^^ s.l17 ^^^ s.l22
  let c3 := s.l3 ^^^ s.l8 ^^^ s.l13 ^^^ s.l18 ^^^ s.l23
  let c4 := s.l4 ^^^ s.l9 ^^^ s.l14 ^^^ s.l19 ^^^ s.l24
  let d0 := c4 ^^^ rot c1 1#u32
  let d1 := c0 ^^^ rot c2 1#u32
  let d2 := c1 ^^^ rot c3 1#u32
  let d3 := c2 ^^^ rot c4 1#u32
  let d4 := c3 ^^^ rot c0 1#u32
  ⟨s.l0 ^^^ d0, s.l1 ^^^ d1, s.l2 ^^^ d2, s.l3 ^^^ d3, s.l4 ^^^ d4,
   s.l5 ^^^ d0, s.l6 ^^^ d1, s.l7 ^^^ d2, s.l8 ^^^ d3, s.l9 ^^^ d4,
   s.l10 ^^^ d0, s.l11 ^^^ d1, s.l12 ^^^ d2, s.l13 ^^^ d3, s.l14 ^^^ d4,
   s.l15 ^^^ d0, s.l16 ^^^ d1, s.l17 ^^^ d2, s.l18 ^^^ d3, s.l19 ^^^ d4,
   s.l20 ^^^ d0, s.l21 ^^^ d1, s.l22 ^^^ d2, s.l23 ^^^ d3, s.l24 ^^^ d4⟩

/-- ρ core: per-lane rotation by fixed offsets. -/
def rhoCore (s : Lanes25) : Lanes25 :=
  ⟨s.l0,            rot s.l1  1#u32,  rot s.l2  62#u32, rot s.l3  28#u32, rot s.l4  27#u32,
   rot s.l5  36#u32, rot s.l6  44#u32, rot s.l7  6#u32,  rot s.l8  55#u32, rot s.l9  20#u32,
   rot s.l10 3#u32,  rot s.l11 10#u32, rot s.l12 43#u32, rot s.l13 25#u32, rot s.l14 39#u32,
   rot s.l15 41#u32, rot s.l16 45#u32, rot s.l17 15#u32, rot s.l18 21#u32, rot s.l19 8#u32,
   rot s.l20 18#u32, rot s.l21 2#u32,  rot s.l22 61#u32, rot s.l23 56#u32, rot s.l24 14#u32⟩

/-- π core: lane permutation. A'[x,y] = A[(x+3y)%5, x]. -/
def piCore (s : Lanes25) : Lanes25 :=
  ⟨s.l0,  s.l6,  s.l12, s.l18, s.l24,
   s.l3,  s.l9,  s.l10, s.l16, s.l22,
   s.l1,  s.l7,  s.l13, s.l19, s.l20,
   s.l4,  s.l5,  s.l11, s.l17, s.l23,
   s.l2,  s.l8,  s.l14, s.l15, s.l21⟩

/-- χ core: non-linear step. Per-row: s[x] ^^^ (~~~s[x+1] &&& s[x+2]). -/
def chiCore (s : Lanes25) : Lanes25 :=
  ⟨s.l0 ^^^ (~~~s.l1 &&& s.l2), s.l1 ^^^ (~~~s.l2 &&& s.l3), s.l2 ^^^ (~~~s.l3 &&& s.l4),
   s.l3 ^^^ (~~~s.l4 &&& s.l0), s.l4 ^^^ (~~~s.l0 &&& s.l1),
   s.l5 ^^^ (~~~s.l6 &&& s.l7), s.l6 ^^^ (~~~s.l7 &&& s.l8), s.l7 ^^^ (~~~s.l8 &&& s.l9),
   s.l8 ^^^ (~~~s.l9 &&& s.l5), s.l9 ^^^ (~~~s.l5 &&& s.l6),
   s.l10 ^^^ (~~~s.l11 &&& s.l12), s.l11 ^^^ (~~~s.l12 &&& s.l13), s.l12 ^^^ (~~~s.l13 &&& s.l14),
   s.l13 ^^^ (~~~s.l14 &&& s.l10), s.l14 ^^^ (~~~s.l10 &&& s.l11),
   s.l15 ^^^ (~~~s.l16 &&& s.l17), s.l16 ^^^ (~~~s.l17 &&& s.l18), s.l17 ^^^ (~~~s.l18 &&& s.l19),
   s.l18 ^^^ (~~~s.l19 &&& s.l15), s.l19 ^^^ (~~~s.l15 &&& s.l16),
   s.l20 ^^^ (~~~s.l21 &&& s.l22), s.l21 ^^^ (~~~s.l22 &&& s.l23), s.l22 ^^^ (~~~s.l23 &&& s.l24),
   s.l23 ^^^ (~~~s.l24 &&& s.l20), s.l24 ^^^ (~~~s.l20 &&& s.l21)⟩

/-! ## Core-to-spec bridge -/

theorem thetaCore_get (s : Lanes25) (x y : Fin 5) :
    (thetaCore s).get x y = s.get x y ^^^
      (s.get (x-1) 0 ^^^ s.get (x-1) 1 ^^^ s.get (x-1) 2 ^^^ s.get (x-1) 3 ^^^ s.get (x-1) 4 ^^^
       rot (s.get (x+1) 0 ^^^ s.get (x+1) 1 ^^^ s.get (x+1) 2 ^^^ s.get (x+1) 3 ^^^ s.get (x+1) 4) 1#u32) := by
  simp only [thetaCore, Lanes25.get, Fin.add_def, Fin.sub_def, rot]
  revert x y
  apply Fin5x5_cases <;> simp only [Lanes25.get, Fin.isValue, Nat.reduceMod, Nat.reduceSub, Nat.reduceAdd, Fin.val_zero, Fin.val_one]

theorem thetaCore_toState (s : Lanes25) :
    (thetaCore s).toState = SHA3.θ s.toState := by
  simp only [Lanes25.toState, SHA3.θ]
  apply Vector.ofFn_congr; intro x
  apply Vector.ofFn_congr; intro y
  rw [thetaCore_get]
  simp only [toLane_xor, toLane_rotate, Vector.getElem_ofFn, Fin.getElem_fin]
  revert x y
  apply Fin5x5_cases <;> simp only [Lanes25.get, Fin.add_def, Fin.sub_def, Lane_xor_assoc, u32_one_toNat, Fin.isValue, Nat.reduceMod, Nat.reduceSub, Nat.reduceAdd, Fin.val_zero, Fin.val_one]

theorem rhoCore_get (s : Lanes25) (x y : Fin 5) :
    (rhoCore s).get x y = rot (s.get x y)
      (match x, y with
      | ⟨0,_⟩,⟨0,_⟩ => 0#u32  | ⟨1,_⟩,⟨0,_⟩ => 1#u32  | ⟨2,_⟩,⟨0,_⟩ => 62#u32 | ⟨3,_⟩,⟨0,_⟩ => 28#u32 | ⟨4,_⟩,⟨0,_⟩ => 27#u32
      | ⟨0,_⟩,⟨1,_⟩ => 36#u32 | ⟨1,_⟩,⟨1,_⟩ => 44#u32 | ⟨2,_⟩,⟨1,_⟩ => 6#u32  | ⟨3,_⟩,⟨1,_⟩ => 55#u32 | ⟨4,_⟩,⟨1,_⟩ => 20#u32
      | ⟨0,_⟩,⟨2,_⟩ => 3#u32  | ⟨1,_⟩,⟨2,_⟩ => 10#u32 | ⟨2,_⟩,⟨2,_⟩ => 43#u32 | ⟨3,_⟩,⟨2,_⟩ => 25#u32 | ⟨4,_⟩,⟨2,_⟩ => 39#u32
      | ⟨0,_⟩,⟨3,_⟩ => 41#u32 | ⟨1,_⟩,⟨3,_⟩ => 45#u32 | ⟨2,_⟩,⟨3,_⟩ => 15#u32 | ⟨3,_⟩,⟨3,_⟩ => 21#u32 | ⟨4,_⟩,⟨3,_⟩ => 8#u32
      | ⟨0,_⟩,⟨4,_⟩ => 18#u32 | ⟨1,_⟩,⟨4,_⟩ => 2#u32  | ⟨2,_⟩,⟨4,_⟩ => 61#u32 | ⟨3,_⟩,⟨4,_⟩ => 56#u32 | ⟨4,_⟩,⟨4,_⟩ => 14#u32) := by
  simp only [rhoCore, Lanes25.get]
  revert x y
  apply Fin5x5_cases <;> simp only [rot_zero]

@[simp] private theorem Lane_rotateLeft_zero (v : SHA3.Lane) : v.rotateLeft 0 = v := by
  unfold Vector.rotateLeft
  simp only [show (64 : Nat) ≠ 0 from by omega, ↓reduceDIte]
  apply Vector.ext; intro i hi
  simp only [Vector.getElem_ofFn, Nat.zero_mod, Nat.sub_zero]
  congr 1; rw [Nat.add_mod_right, Nat.mod_eq_of_lt hi]

/-- If rotation amounts are equal, rotations of the same lane are equal. -/
theorem Lane_rotateLeft_congr (v : SHA3.Lane) (a b : Nat) (h : a = b) :
    v.rotateLeft a = v.rotateLeft b := h ▸ rfl

theorem rhoCore_toState (s : Lanes25) :
    (rhoCore s).toState = SHA3.ρ (s.toState) := by
  simp only [Lanes25.toState, SHA3.ρ, SHA3.rhoOffsets_eq_table2]
  apply Vector.ofFn_congr; intro x
  apply Vector.ofFn_congr; intro y
  rw [rhoCore_get, toLane_rotate]
  simp only [Vector.getElem_ofFn, Fin.getElem_fin, Lanes25.get]
  revert x y
  apply Fin5x5_cases <;> (apply Lane_rotateLeft_congr; decide)

theorem piCore_get (s : Lanes25) (x y : Fin 5) :
    (piCore s).get x y = s.get (x + 3*y) x := by
  simp only [piCore, Lanes25.get, Fin.add_def, Fin.mul_def]
  revert x y
  apply Fin5x5_cases <;> ring_nf

theorem piCore_toState (s : Lanes25) :
    (piCore s).toState = SHA3.π (s.toState) := by
  simp only [Lanes25.toState, SHA3.π]
  apply Vector.ofFn_congr; intro x
  apply Vector.ofFn_congr; intro y
  rw [piCore_get]
  simp only [Vector.getElem_ofFn, Fin.getElem_fin]

theorem chiCore_get (s : Lanes25) (x y : Fin 5) :
    (chiCore s).get x y = s.get x y ^^^ (~~~(s.get (x+1) y) &&& s.get (x+2) y) := by
  simp only [chiCore, Lanes25.get, Fin.add_def]
  revert x y
  apply Fin5x5_cases <;> ring_nf

theorem chiCore_toState (s : Lanes25) :
    (chiCore s).toState = SHA3.χ (s.toState) := by
  simp only [Lanes25.toState, SHA3.χ]
  apply Vector.ofFn_congr; intro x
  apply Vector.ofFn_congr; intro y
  rw [chiCore_get]
  simp only [toLane_xor, toLane_and, toLane_not, Vector.getElem_ofFn, Fin.getElem_fin]

/-! ## Fused round on Lanes25 -/

/-- Apply `Rnd` for rounds `[0 ..< n)` to a state. -/
def iterateRnd (A : SHA3.State) (n : Nat) : SHA3.State :=
  match n with
  | 0 => A
  | n + 1 => SHA3.Rnd (iterateRnd A n) n

/-- Core fused χ∘π∘ρ∘θ on 25 individual U64 lanes. -/
def fusedCore (s : Lanes25) : Lanes25 :=
  let rot := core.num.U64.rotate_left
  let c0 := s.l0 ^^^ s.l5 ^^^ s.l10 ^^^ s.l15 ^^^ s.l20
  let c1 := s.l1 ^^^ s.l6 ^^^ s.l11 ^^^ s.l16 ^^^ s.l21
  let c2 := s.l2 ^^^ s.l7 ^^^ s.l12 ^^^ s.l17 ^^^ s.l22
  let c3 := s.l3 ^^^ s.l8 ^^^ s.l13 ^^^ s.l18 ^^^ s.l23
  let c4 := s.l4 ^^^ s.l9 ^^^ s.l14 ^^^ s.l19 ^^^ s.l24
  let d0 := c4 ^^^ rot c1 1#u32
  let d1 := c0 ^^^ rot c2 1#u32
  let d2 := c1 ^^^ rot c3 1#u32
  let d3 := c2 ^^^ rot c4 1#u32
  let d4 := c3 ^^^ rot c0 1#u32
  let t0  := s.l0  ^^^ d0
  let t1  := rot (s.l6  ^^^ d1) 44#u32
  let t2  := rot (s.l12 ^^^ d2) 43#u32
  let t3  := rot (s.l18 ^^^ d3) 21#u32
  let t4  := rot (s.l24 ^^^ d4) 14#u32
  let t5  := rot (s.l3  ^^^ d3) 28#u32
  let t10 := rot (s.l1  ^^^ d1) 1#u32
  let t15 := rot (s.l4  ^^^ d4) 27#u32
  let t20 := rot (s.l2  ^^^ d2) 62#u32
  let s0' := t0 ^^^ (~~~t1 &&& t2)
  let s1' := t1 ^^^ (~~~t2 &&& t3)
  let s2' := t2 ^^^ (~~~t3 &&& t4)
  let s3' := t3 ^^^ (~~~t4 &&& t0)
  let s4' := t4 ^^^ (~~~t0 &&& t1)
  let t6  := rot (s.l9  ^^^ d4) 20#u32
  let t7  := rot (s.l10 ^^^ d0) 3#u32
  let t8  := rot (s.l16 ^^^ d1) 45#u32
  let t9  := rot (s.l22 ^^^ d2) 61#u32
  let t11 := rot (s.l7  ^^^ d2) 6#u32
  let t16 := rot (s.l5  ^^^ d0) 36#u32
  let t21 := rot (s.l8  ^^^ d3) 55#u32
  let s5' := t5  ^^^ (~~~t6 &&& t7)
  let s6' := t6  ^^^ (~~~t7 &&& t8)
  let s7' := t7  ^^^ (~~~t8 &&& t9)
  let s8' := t8  ^^^ (~~~t9 &&& t5)
  let s9' := t9  ^^^ (~~~t5 &&& t6)
  let t12 := rot (s.l13 ^^^ d3) 25#u32
  let t13 := rot (s.l19 ^^^ d4) 8#u32
  let t14 := rot (s.l20 ^^^ d0) 18#u32
  let t17 := rot (s.l11 ^^^ d1) 10#u32
  let t22 := rot (s.l14 ^^^ d4) 39#u32
  let s10' := t10 ^^^ (~~~t11 &&& t12)
  let s11' := t11 ^^^ (~~~t12 &&& t13)
  let s12' := t12 ^^^ (~~~t13 &&& t14)
  let s13' := t13 ^^^ (~~~t14 &&& t10)
  let s14' := t14 ^^^ (~~~t10 &&& t11)
  let t18 := rot (s.l17 ^^^ d2) 15#u32
  let t19 := rot (s.l23 ^^^ d3) 56#u32
  let t23 := rot (s.l15 ^^^ d0) 41#u32
  let s15' := t15 ^^^ (~~~t16 &&& t17)
  let s16' := t16 ^^^ (~~~t17 &&& t18)
  let s17' := t17 ^^^ (~~~t18 &&& t19)
  let s18' := t18 ^^^ (~~~t19 &&& t15)
  let s19' := t19 ^^^ (~~~t15 &&& t16)
  let t24 := rot (s.l21 ^^^ d1) 2#u32
  let s20' := t20 ^^^ (~~~t21 &&& t22)
  let s21' := t21 ^^^ (~~~t22 &&& t23)
  let s22' := t22 ^^^ (~~~t23 &&& t24)
  let s23' := t23 ^^^ (~~~t24 &&& t20)
  let s24' := t24 ^^^ (~~~t20 &&& t21)
  ⟨s0', s1', s2', s3', s4', s5', s6', s7', s8', s9',
   s10', s11', s12', s13', s14', s15', s16', s17', s18', s19',
   s20', s21', s22', s23', s24'⟩

theorem fusedCore_eq_composed (s : Lanes25) :
    fusedCore s = chiCore (piCore (rhoCore (thetaCore s))) := by
  simp only [fusedCore, chiCore, piCore, rhoCore, thetaCore]

/-- The fused χ∘π∘ρ∘θ on Lanes25 matches the spec composition. -/
theorem fusedCore_toState (s : Lanes25) :
    (fusedCore s).toState = SHA3.χ (SHA3.π (SHA3.ρ (SHA3.θ s.toState))) := by
  rw [fusedCore_eq_composed, chiCore_toState, piCore_toState, rhoCore_toState, thetaCore_toState]

set_option maxHeartbeats 800000 in
theorem iota_k_eq_RC (ir : Fin 24) :
    toLane (KECCAK_IOTA_K[ir]) = SHA3.ι.RC ir := by
  fin_cases ir <;> (unfold KECCAK_IOTA_K; native_decide)

/-- Iota per-lane: only lane (0,0) is XOR'd with the round constant. -/
theorem iotaCore_get (s : Lanes25) (rc : U64) (x y : Fin 5) :
    { s with l0 := s.l0 ^^^ rc }.get x y =
    if x = 0 ∧ y = 0 then s.l0 ^^^ rc else s.get x y := by
  simp only [Lanes25.get]
  revert x y
  apply Fin5x5_cases <;> simp

/-- Iota on Lanes25 matches the spec ι step. -/
theorem toState_iota (s : Lanes25) (rc : U64) (ir : Nat)
    (hrc : toLane rc = SHA3.ι.RC ir) :
    { s with l0 := s.l0 ^^^ rc }.toState = SHA3.ι s.toState ir := by
  simp only [SHA3.ι, Lanes25.toState]
  apply Vector.ofFn_congr; intro x
  apply Vector.ofFn_congr; intro y
  rw [iotaCore_get]
  simp only [Vector.getElem_ofFn, Fin.getElem_fin]
  split
  · obtain ⟨rfl, rfl⟩ := ‹_ ∧ _›; simp [Lanes25.get, toLane_xor, hrc]
  · rfl

/-- A full fused round (χ∘π∘ρ∘θ + ι) on Lanes25 matches the spec Rnd. -/
theorem fusedRoundCore_toState (s : Lanes25) (ir : Nat) (hir : ir < 24) :
    { fusedCore s with l0 := (fusedCore s).l0 ^^^ KECCAK_IOTA_K[ir] }.toState =
    SHA3.Rnd s.toState ir := by
  simp only [SHA3.Rnd, ← fusedCore_toState]
  exact toState_iota _ _ ir (iota_k_eq_RC ⟨ir, hir⟩)

/-- One fused round on Lanes25: χ∘π∘ρ∘θ + XOR round constant into l0. -/
def fusedRoundCore (s : Lanes25) (rc : U64) : Lanes25 :=
  { fusedCore s with l0 := (fusedCore s).l0 ^^^ rc }

/-- fusedRoundCore with the k-th round constant matches spec Rnd. -/
theorem fusedRoundCore_toState' (s : Lanes25) (ir : Nat) (hir : ir < 24) :
    (fusedRoundCore s (KECCAK_IOTA_K[ir])).toState = SHA3.Rnd s.toState ir := by
  simp only [fusedRoundCore]
  exact fusedRoundCore_toState s ir hir

/-- Iterated fused rounds on Lanes25. -/
def iterateRndCore (s : Lanes25) (n : Nat) (hn : n ≤ 24 := by omega) : Lanes25 :=
  match n with
  | 0 => s
  | n + 1 => fusedRoundCore (iterateRndCore s n (by omega)) (KECCAK_IOTA_K[n])

/-- iterateRndCore lifts to iterateRnd via toState. -/
theorem iterateRndCore_toState (s : Lanes25) (n : Nat) (hn : n ≤ 24) :
    (iterateRndCore s n hn).toState = iterateRnd s.toState n := by
  induction n with
  | zero => simp [iterateRndCore, iterateRnd]
  | succ k ih =>
    simp only [iterateRndCore, iterateRnd]
    rw [fusedRoundCore_toState' _ k (by omega), ih (by omega)]

/-- Step lemma for the loop proof: expresses iterateRndCore (n+1) using
    `KECCAK_IOTA_K.val[n]!` (the form produced by fold_fused_round_body). -/
theorem iterateRndCore_succ (s : Lanes25) (n : Nat) (hn : n + 1 ≤ 24) :
    iterateRndCore s (n + 1) hn =
      fusedRoundCore (iterateRndCore s n (by omega)) (KECCAK_IOTA_K.val[n]) := by
  simp only [iterateRndCore]; grind

end symcrust
