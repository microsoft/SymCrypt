/-
  # Bridges/NttLinearity.lean — NTT linearity over `Zq` scalars (ML-KEM, FIPS 203).

  Tracks divergence category **D2** (NTT linearity, dual of MLDSA's category).

  ## Why this file exists

  The `MLKEM.NTT` and `MLKEM.NTTInv` (Algorithms 9 and 10) are
  linear over `Zq`: multiplying a polynomial by a scalar `c : Zq` and then
  taking its NTT is the same as taking the NTT first and scaling each
  coefficient by `c` componentwise.

      Spec.NTT (Polynomial.scalarMul p c)
        = (Spec.NTT p).map (c * ·)

  This is needed in several places:

  * `K_PKE.Encrypt`: the spec writes `Decompress dᵤ u + 2^{dᵤ-1}·…`; the
    impl computes the scalar factor *after* taking the NTT.
  * `vector_mul_r` / `poly_element_mul_r`: scale every coefficient by
    `R` (Montgomery factor) — this is just `Polynomial.scalarMul p R`
    composed with whatever shape the polynomial is in.
  * Inner-product Mont cancellation: when an `Rinv` factor needs to be
    distributed across a sum of `MultiplyNTTs` products.

  Beyond simple linearity, we also need:

  * `MultiplyNTTs` distributes over componentwise scalar multiplication.
  * `BaseCaseMultiply` is multilinear in each coefficient.
  * The round-trip `NTTInv ∘ NTT = id`, modulo the `f := 3303 ≡ 128⁻¹`
    factor that the spec's `NTTInv` already absorbs (FIPS 203 Algorithm 10
    line 19).

  Note (ML-KEM specific): unlike MLDSA, ML-KEM's NTT acts on 128 *pairs*
  of base polynomials (Algorithm 9, layer count = 7). The post-NTTInv
  fixup is `128⁻¹` (not `256⁻¹` as in MLDSA). See `Bridges/MontArith.lean`
  for the corresponding `INTT_FIXUP_TIMES_RSQR_zq` identity.
-/
import Symcrust.Properties.MLKEM.Basic
import Symcrust.Properties.MLKEM.Bridges.MontArith
import Symcrust.Properties.MLKEM.Ntt.NttSpecAux

open Spec
open Spec.MLKEM
open Aeneas Aeneas.Std
open Symcrust.Properties.MLKEM.Ntt

namespace Symcrust.Properties.MLKEM.Bridges

set_option maxHeartbeats 1000000

/-! ## Helper: `Vector.map` commutes with `Vector.set!` -/

private theorem Vector.map_set! {α : Type*} [Inhabited α] {n : Nat} (g : α → α)
    (v : Vector α n) (i : Nat) (x : α) :
    (v.set! i x).map g = (v.map g).set! i (g x) := by
  apply _root_.Vector.ext; intro j hj
  simp_lists
  by_cases hij : i = j <;> simp_lists [hij]

/-! ## D2 — Linearity of `MLKEM.NTT` -/

/-- Linearity at the inner butterfly recursion: scalar-multiplying the
input commutes with `nttLayerInner` because every butterfly transform
`(c0, c1) ↦ (c0 + c1·ζ, c0 - c1·ζ)` is `Zq`-linear in `(c0, c1)`. -/
private theorem nttLayerInner_scalarMul (c : Zq) (f : Polynomial)
    (i len start j : Nat) :
    nttLayerInner (f.map (c * ·)) i len start j
      = (nttLayerInner f i len start j).map (c * ·) := by
  unfold nttLayerInner
  simp only
  split
  · rename_i hj
    have hread : ∀ (p : Nat), (Vector.map (fun x => c * x) f)[p]! = c * f[p]! := by
      intro p
      by_cases hp : p < 256
      · rw [getElem!_pos (Vector.map _ f) _ hp, Vector.getElem_map, getElem!_pos f _ hp]
      · rw [getElem!_neg (Vector.map _ f) _ hp, getElem!_neg f _ hp]
        show (default : Zq) = c * (default : Zq)
        show (0 : Zq) = c * 0
        ring
    have key : ∀ (a b : Nat) (x y : Zq),
        ((Vector.map (fun w => c * w) f).set! a (c * x)).set! b (c * y)
          = Vector.map (fun w => c * w) ((f.set! a x).set! b y) := by
      intro a b x y
      rw [Vector.map_set! (fun w => c * w) (f.set! a x) b y]
      rw [Vector.map_set! (fun w => c * w) f a x]
    rw [hread, hread]
    have hadd : c * f[start + j]! + c * f[start + j + len]! * ζ ^ bitRev 7 i
        = c * (f[start + j]! + f[start + j + len]! * ζ ^ bitRev 7 i) := by ring
    have hsub : c * f[start + j]! - c * f[start + j + len]! * ζ ^ bitRev 7 i
        = c * (f[start + j]! - f[start + j + len]! * ζ ^ bitRev 7 i) := by ring
    rw [hadd, hsub, key]
    exact nttLayerInner_scalarMul c _ i len start (j + 1)
  · rfl
termination_by len - j
decreasing_by agrind

/-- Linearity at the middle loop: induction over the start of each pair-window. -/
private theorem nttLayer_scalarMul (c : Zq) (f : Polynomial)
    (i len start : Nat) (hLen : 0 < len) :
    nttLayer (f.map (c * ·)) i len start hLen
      = (nttLayer f i len start hLen).map (c * ·) := by
  unfold nttLayer
  split
  · rw [nttLayerInner_scalarMul]
    exact nttLayer_scalarMul c _ (i + 1) len (start + 2 * len) hLen
  · rfl
termination_by 256 - start
decreasing_by agrind

/-- Linearity of the recursive `ntt` — composition of seven layers. -/
private theorem ntt_scalarMul (c : Zq) (f : Polynomial) :
    ntt (f.map (c * ·)) = (ntt f).map (c * ·) := by
  unfold ntt
  simp only [nttLayer_scalarMul]

/-- **D2.1** — Forward NTT is linear over `Zq`.

For any polynomial `f : Polynomial` and scalar `c : Zq`,

    NTT (f.map (c * ·)) = (NTT f).map (c * ·)

Informal proof: by induction on the seven NTT layers. At each layer,
every butterfly does `(a, b) ↦ (a + ζ·b, a - ζ·b)`. If we replace `a` by
`c·a` and `b` by `c·b` throughout, the result is `(c·a + ζ·(c·b),
c·a - ζ·(c·b)) = c · (a + ζ·b, a - ζ·b)`. So one butterfly commutes with
scalar multiplication; by induction over the inner loop, the inner
butterfly loop commutes; by induction over the middle/outer loops, the
whole layer commutes; by induction over the seven layers, NTT commutes.

Mechanization path: prove `nttLayerInner_scalarMul`, `nttLayer_scalarMul`,
`ntt_scalarMul`, then bridge to `MLKEM.NTT` via `ntt_eq` from
`NttSpecAux`. -/
theorem NTT_scalarMul (c : Zq) (f : Polynomial) :
    MLKEM.NTT (f.map (c * ·)) = (MLKEM.NTT f).map (c * ·) := by
  rw [← ntt_eq, ← ntt_eq]
  exact ntt_scalarMul c f

/-- Linearity at the INTT inner butterfly recursion. -/
private theorem invNttLayerInner_scalarMul (c : Zq) (f : Polynomial)
    (i len start j : Nat) :
    invNttLayerInner (f.map (c * ·)) i len start j
      = (invNttLayerInner f i len start j).map (c * ·) := by
  unfold invNttLayerInner
  simp only
  split
  · rename_i hj
    have hread : ∀ (p : Nat), (Vector.map (fun x => c * x) f)[p]! = c * f[p]! := by
      intro p
      by_cases hp : p < 256
      · rw [getElem!_pos (Vector.map _ f) _ hp, Vector.getElem_map, getElem!_pos f _ hp]
      · rw [getElem!_neg (Vector.map _ f) _ hp, getElem!_neg f _ hp]
        show (default : Zq) = c * (default : Zq)
        show (0 : Zq) = c * 0
        ring
    have key : ∀ (a b : Nat) (x y : Zq),
        ((Vector.map (fun w => c * w) f).set! a (c * x)).set! b (c * y)
          = Vector.map (fun w => c * w) ((f.set! a x).set! b y) := by
      intro a b x y
      rw [Vector.map_set! (fun w => c * w) (f.set! a x) b y]
      rw [Vector.map_set! (fun w => c * w) f a x]
    rw [hread, hread]
    have hadd : c * f[start + j]! + c * f[start + j + len]!
        = c * (f[start + j]! + f[start + j + len]!) := by ring
    have hgs : ζ ^ bitRev 7 i * (c * f[start + j + len]! - c * f[start + j]!)
        = c * (ζ ^ bitRev 7 i * (f[start + j + len]! - f[start + j]!)) := by ring
    rw [hadd, hgs, key]
    exact invNttLayerInner_scalarMul c _ i len start (j + 1)
  · rfl
termination_by len - j
decreasing_by agrind

/-- Linearity at the INTT middle loop. -/
private theorem invNttLayer_scalarMul (c : Zq) (f : Polynomial)
    (i len start : Nat) (hLen : 0 < len) :
    invNttLayer (f.map (c * ·)) i len start hLen
      = (invNttLayer f i len start hLen).map (c * ·) := by
  unfold invNttLayer
  split
  · rw [invNttLayerInner_scalarMul]
    exact invNttLayer_scalarMul c _ (i - 1) len (start + 2 * len) hLen
  · rfl
termination_by 256 - start
decreasing_by agrind

/-- Linearity of the recursive `invNtt` — composition of seven layers. -/
private theorem invNtt_scalarMul (c : Zq) (f : Polynomial) :
    invNtt (f.map (c * ·)) = (invNtt f).map (c * ·) := by
  unfold invNtt
  simp only [invNttLayer_scalarMul]

/-- **D2.2** — Inverse NTT is linear over `Zq`.

For any `fh : Polynomial` and scalar `c : Zq`,

    NTTInv (fh.map (c * ·)) = (NTTInv fh).map (c * ·)

Informal proof: same structure as D2.1, with Gentleman–Sande butterflies
in place of Cooley–Tukey. The final `* (3303 : Zq) = * 128⁻¹` fixup
(Algorithm 10 line 19) also commutes with scalar multiplication —
`(c·x) · 128⁻¹ = c · (x · 128⁻¹)`. -/
theorem NTTInv_scalarMul (c : Zq) (fh : Polynomial) :
    MLKEM.NTTInv (fh.map (c * ·)) = (MLKEM.NTTInv fh).map (c * ·) := by
  rw [invNtt_eq_ntt_inv, invNtt_eq_ntt_inv, invNtt_scalarMul]
  have hmap : ∀ (v : Polynomial) (i : Nat), i < 256 →
      (Vector.map (fun x => c * x) v)[i]! = c * v[i]! := by
    intro v i hi
    rw [getElem!_pos (Vector.map _ v) _ hi, Vector.getElem_map, getElem!_pos v _ hi]
  rw [Polynomial.eq_iff]
  intro i hi
  rw [Polynomial.getElem!_mul, hmap _ _ hi, hmap _ _ hi, Polynomial.getElem!_mul]
  ring

/-! ## D2.3 — Round-trip identity

Proof strategy: both `NTT` and `NTTInv` are additive and commute with
scalar multiplication (D2.1, D2.2).  A polynomial `f` decomposes as a
sum of scaled basis vectors `f[i] · eᵢ`.  Computational verification
(`native_decide`) confirms `NTTInv (NTT eᵢ) = eᵢ` for all 256 basis
vectors.  Combining additivity + scalar linearity + basis check gives
the general result.  `NTT_NTTInv` follows by the same argument
(separate `native_decide` check). -/

/- Pointwise addition for Polynomial: `(f + g)[j] = f[j] + g[j]`. -/
private theorem getElem_add' (f g : Polynomial) (j : Nat) (hj : j < 256) :
    (f + g)[j] = f[j] + g[j] := by
  show (Vector.zipWith (· + ·) f g)[j] = _; rw [Vector.getElem_zipWith]

/- Double `set!` distributes over addition. -/
private theorem double_set!_add (f g : Polynomial) (a b : Nat)
    (x1 y1 x2 y2 : Zq) :
    ((f.set! a x1).set! b y1) + ((g.set! a x2).set! b y2)
      = ((f + g).set! a (x1 + x2)).set! b (y1 + y2) := by
  apply _root_.Vector.ext; intro j hj
  show (Vector.zipWith (· + ·) _ _)[j] = _; rw [Vector.getElem_zipWith]
  by_cases hbj : b = j <;> by_cases haj : a = j <;>
    subst_eqs <;> simp_lists [*]
  exact (getElem_add' f g j hj).symm

/- Forward NTT butterfly additivity. -/
private theorem nttLayerInner_add (f g : Polynomial) (i len start j : Nat) :
    nttLayerInner (f + g) i len start j
      = nttLayerInner f i len start j + nttLayerInner g i len start j := by
  unfold nttLayerInner; simp only; split
  · rename_i hj
    have hread : ∀ (p : Nat), (f + g)[p]! = f[p]! + g[p]! := by
      intro p; by_cases hp : p < 256
      · rw [getElem!_pos (f + g) _ hp, getElem!_pos f _ hp, getElem!_pos g _ hp]
        exact getElem_add' f g p hp
      · rw [getElem!_neg (f + g) _ hp, getElem!_neg f _ hp, getElem!_neg g _ hp]
        show (0 : Zq) = 0 + 0; ring
    rw [hread, hread,
      show f[start + j]! + g[start + j]!
         + (f[start + j + len]! + g[start + j + len]!) * ζ ^ bitRev 7 i
        = (f[start + j]! + f[start + j + len]! * ζ ^ bitRev 7 i)
        + (g[start + j]! + g[start + j + len]! * ζ ^ bitRev 7 i) from by ring,
      show f[start + j]! + g[start + j]!
         - (f[start + j + len]! + g[start + j + len]!) * ζ ^ bitRev 7 i
        = (f[start + j]! - f[start + j + len]! * ζ ^ bitRev 7 i)
        + (g[start + j]! - g[start + j + len]! * ζ ^ bitRev 7 i) from by ring,
      ← double_set!_add]
    exact nttLayerInner_add _ _ i len start (j + 1)
  · rfl
termination_by len - j
decreasing_by agrind

private theorem nttLayer_add (f g : Polynomial) (i len start : Nat)
    (hLen : 0 < len) :
    nttLayer (f + g) i len start hLen
      = nttLayer f i len start hLen + nttLayer g i len start hLen := by
  unfold nttLayer; split
  · rw [nttLayerInner_add]
    exact nttLayer_add _ _ (i + 1) len (start + 2 * len) hLen
  · rfl
termination_by 256 - start
decreasing_by agrind

private theorem ntt_add (f g : Polynomial) :
    ntt (f + g) = ntt f + ntt g := by
  unfold ntt; simp only [nttLayer_add]

theorem NTT_add (f g : Polynomial) :
    MLKEM.NTT (f + g) = MLKEM.NTT f + MLKEM.NTT g := by
  rw [← ntt_eq, ← ntt_eq, ← ntt_eq]; exact ntt_add f g

/- Inverse NTT butterfly additivity. -/
private theorem invNttLayerInner_add (f g : Polynomial)
    (i len start j : Nat) :
    invNttLayerInner (f + g) i len start j
      = invNttLayerInner f i len start j
      + invNttLayerInner g i len start j := by
  unfold invNttLayerInner; simp only; split
  · rename_i hj
    have hread : ∀ (p : Nat), (f + g)[p]! = f[p]! + g[p]! := by
      intro p; by_cases hp : p < 256
      · rw [getElem!_pos (f + g) _ hp, getElem!_pos f _ hp, getElem!_pos g _ hp]
        exact getElem_add' f g p hp
      · rw [getElem!_neg (f + g) _ hp, getElem!_neg f _ hp, getElem!_neg g _ hp]
        show (0 : Zq) = 0 + 0; ring
    rw [hread, hread,
      show (f[start + j]! + g[start + j]!)
         + (f[start + j + len]! + g[start + j + len]!)
        = (f[start + j]! + f[start + j + len]!)
        + (g[start + j]! + g[start + j + len]!) from by ring,
      show ζ ^ bitRev 7 i
         * ((f[start + j + len]! + g[start + j + len]!)
           - (f[start + j]! + g[start + j]!))
        = ζ ^ bitRev 7 i * (f[start + j + len]! - f[start + j]!)
        + ζ ^ bitRev 7 i * (g[start + j + len]! - g[start + j]!)
        from by ring,
      ← double_set!_add]
    exact invNttLayerInner_add _ _ i len start (j + 1)
  · rfl
termination_by len - j
decreasing_by agrind

private theorem invNttLayer_add (f g : Polynomial) (i len start : Nat)
    (hLen : 0 < len) :
    invNttLayer (f + g) i len start hLen
      = invNttLayer f i len start hLen + invNttLayer g i len start hLen := by
  unfold invNttLayer; split
  · rw [invNttLayerInner_add]
    exact invNttLayer_add _ _ (i - 1) len (start + 2 * len) hLen
  · rfl
termination_by 256 - start
decreasing_by agrind

private theorem invNtt_add (f g : Polynomial) :
    invNtt (f + g) = invNtt f + invNtt g := by
  unfold invNtt; simp only [invNttLayer_add]

theorem NTTInv_add (f g : Polynomial) :
    MLKEM.NTTInv (f + g) = MLKEM.NTTInv f + MLKEM.NTTInv g := by
  rw [invNtt_eq_ntt_inv, invNtt_eq_ntt_inv, invNtt_eq_ntt_inv, invNtt_add]
  show (invNtt f + invNtt g).map (· * (3303 : Zq))
     = (invNtt f).map (· * (3303 : Zq)) + (invNtt g).map (· * (3303 : Zq))
  apply _root_.Vector.ext; intro j hj
  rw [Vector.getElem_map,
      show ((invNtt f + invNtt g))[j]
         = (Vector.zipWith (· + ·) (invNtt f) (invNtt g))[j] from rfl,
      Vector.getElem_zipWith,
      show ((invNtt f).map (· * (3303 : Zq))
          + (invNtt g).map (· * (3303 : Zq)))[j]
         = (Vector.zipWith (· + ·)
             ((invNtt f).map (· * (3303 : Zq)))
             ((invNtt g).map (· * (3303 : Zq))))[j] from rfl,
      Vector.getElem_zipWith, Vector.getElem_map, Vector.getElem_map]
  ring

/- Basis-vector round-trip: `NTTInv (NTT eᵢ) = eᵢ` for all 256 basis
vectors, verified by compiled native code. -/
set_option maxRecDepth 10000 in
set_option maxHeartbeats 20000000 in
private theorem NTTInv_NTT_basis : ∀ i : Fin 256,
    MLKEM.NTTInv (MLKEM.NTT
      (Vector.ofFn fun j : Fin 256 => if j = i then (1 : Zq) else 0))
    = Vector.ofFn (fun j : Fin 256 => if j = i then (1 : Zq) else 0) := by
  native_decide

set_option maxRecDepth 10000 in
set_option maxHeartbeats 20000000 in
private theorem NTT_NTTInv_basis : ∀ i : Fin 256,
    MLKEM.NTT (MLKEM.NTTInv
      (Vector.ofFn fun j : Fin 256 => if j = i then (1 : Zq) else 0))
    = Vector.ofFn (fun j : Fin 256 => if j = i then (1 : Zq) else 0) := by
  native_decide

/- Truncation helper: `trunc n f` keeps the first `n` coefficients of `f`
and zeros the rest.  Used to decompose `f` into a sum of scaled basis
vectors by induction on `n`. -/
private def trunc (n : Nat) (f : Polynomial) : Polynomial :=
  Vector.ofFn fun i : Fin 256 => if i.val < n then f[i.val] else 0

private theorem trunc_zero (f : Polynomial) :
    trunc 0 f = Vector.ofFn (fun _ : Fin 256 => (0 : Zq)) := by
  apply _root_.Vector.ext; intro j hj
  simp [trunc, Vector.getElem_ofFn]

private theorem trunc_256 (f : Polynomial) : trunc 256 f = f := by
  apply _root_.Vector.ext; intro j hj
  simp [trunc]

private theorem trunc_succ (n : Nat) (hn : n < 256) (f : Polynomial) :
    trunc (n + 1) f
    = trunc n f + Vector.ofFn (fun i : Fin 256 =>
        if i = ⟨n, hn⟩ then f[n] else 0) := by
  unfold trunc
  apply _root_.Vector.ext; intro j hj
  show (Vector.ofFn _)[j] = (Vector.zipWith (· + ·) (Vector.ofFn _) (Vector.ofFn _))[j]
  rw [Vector.getElem_ofFn, Vector.getElem_zipWith, Vector.getElem_ofFn, Vector.getElem_ofFn]
  simp only [Fin.mk.injEq]
  by_cases hjn : j < n
  · simp [hjn, show j < n + 1 from by omega,
          show ¬(j = n) from by omega]
  · by_cases hjn1 : j = n
    · simp [hjn1]
    · simp [show ¬(j < n + 1) from by omega, hjn, hjn1]

/- The NTT round-trip on a single scaled basis vector. -/
private theorem NTTInv_NTT_scaled_basis (c : Zq) (n : Fin 256) :
    MLKEM.NTTInv (MLKEM.NTT
      (Vector.ofFn fun i : Fin 256 => if i = n then c else 0))
    = Vector.ofFn (fun i : Fin 256 => if i = n then c else 0) := by
  have h_basis := NTTInv_NTT_basis n
  /- The scaled vector equals `(basis n).map (c * ·)`. -/
  have h_eq : (Vector.ofFn fun i : Fin 256 => if i = n then c else 0)
      = (Vector.ofFn fun i : Fin 256 => if i = n then (1 : Zq) else 0).map
          (c * ·) := by
    apply _root_.Vector.ext; intro j hj
    rw [Vector.getElem_map, Vector.getElem_ofFn, Vector.getElem_ofFn]
    split <;> ring
  rw [h_eq, NTT_scalarMul, NTTInv_scalarMul, h_basis]

/- Inductive step: if `NTTInv (NTT (trunc n f)) = trunc n f`,
then `NTTInv (NTT (trunc (n+1) f)) = trunc (n+1) f`. -/
private theorem NTTInv_NTT_trunc (n : Nat) (hn : n ≤ 256)
    (f : Polynomial) :
    MLKEM.NTTInv (MLKEM.NTT (trunc n f)) = trunc n f := by
  induction n with
  | zero =>
    rw [trunc_zero]
    have : (Vector.ofFn (fun _ : Fin 256 => (0 : Zq)))
        = Vector.ofFn (fun i : Fin 256 => if i = (⟨0, by omega⟩ : Fin 256) then (0 : Zq) else 0) := by
      fcongr 1; ext i; simp
    rw [this]; exact NTTInv_NTT_scaled_basis 0 ⟨0, by omega⟩
  | succ n ih =>
    have hn' : n < 256 := by omega
    rw [trunc_succ n hn' f, NTT_add, NTTInv_add,
        ih (by omega), NTTInv_NTT_scaled_basis f[n] ⟨n, hn'⟩]

/-- **D2.3** — `NTTInv` is the left inverse of `NTT`:  `NTTInv (NTT f) = f`. -/
theorem NTTInv_NTT (f : Polynomial) :
    MLKEM.NTTInv (MLKEM.NTT f) = f := by
  rw [← trunc_256 f]; exact NTTInv_NTT_trunc 256 le_rfl f

/- Symmetric round-trip by the same argument. -/
private theorem NTT_NTTInv_scaled_basis (c : Zq) (n : Fin 256) :
    MLKEM.NTT (MLKEM.NTTInv
      (Vector.ofFn fun i : Fin 256 => if i = n then c else 0))
    = Vector.ofFn (fun i : Fin 256 => if i = n then c else 0) := by
  have h_basis := NTT_NTTInv_basis n
  have h_eq : (Vector.ofFn fun i : Fin 256 => if i = n then c else 0)
      = (Vector.ofFn fun i : Fin 256 => if i = n then (1 : Zq) else 0).map
          (c * ·) := by
    apply _root_.Vector.ext; intro j hj
    rw [Vector.getElem_map, Vector.getElem_ofFn, Vector.getElem_ofFn]
    split <;> ring
  rw [h_eq, NTTInv_scalarMul, NTT_scalarMul, h_basis]

private theorem NTT_NTTInv_trunc (n : Nat) (hn : n ≤ 256)
    (f : Polynomial) :
    MLKEM.NTT (MLKEM.NTTInv (trunc n f)) = trunc n f := by
  induction n with
  | zero =>
    rw [trunc_zero]
    have : (Vector.ofFn (fun _ : Fin 256 => (0 : Zq)))
        = Vector.ofFn (fun i : Fin 256 => if i = (⟨0, by omega⟩ : Fin 256) then (0 : Zq) else 0) := by
      fcongr 1; ext i; simp
    rw [this]; exact NTT_NTTInv_scaled_basis 0 ⟨0, by omega⟩
  | succ n ih =>
    have hn' : n < 256 := by omega
    rw [trunc_succ n hn' f, NTTInv_add, NTT_add,
        ih (by omega), NTT_NTTInv_scaled_basis f[n] ⟨n, hn'⟩]

/-- **D2.3'** — `NTT` is the right inverse of `NTTInv`:  `NTT (NTTInv fh) = fh`. -/
theorem NTT_NTTInv (fh : Polynomial) :
    MLKEM.NTT (MLKEM.NTTInv fh) = fh := by
  rw [← trunc_256 fh]; exact NTT_NTTInv_trunc 256 le_rfl fh

/-! ## D2.4 — `MultiplyNTTs` distributes over scalar multiplication -/

/-- **D2.4.a** — `MultiplyNTTs` distributes over the left scalar factor.

    MultiplyNTTs (fh.map (c * ·)) gh = (MultiplyNTTs fh gh).map (c * ·)

Informal proof: `MultiplyNTTs` is defined as 128 base-case multiplications
on pairs `(fh[2i], fh[2i+1]) · (gh[2i], gh[2i+1])`. Each base case is
`(a₀b₀ + a₁b₁γ, a₀b₁ + a₁b₀)` (FIPS 203 Algorithm 12). Substituting
`(a₀, a₁) ↦ (c·a₀, c·a₁)` gives `c · (a₀b₀ + a₁b₁γ, a₀b₁ + a₁b₀)`.
By 128-case extensionality of the result `Polynomial`. -/
theorem MultiplyNTTs_scalarMul_left (c : Zq) (fh gh : Polynomial) :
    MLKEM.MultiplyNTTs (fh.map (c * ·)) gh
      = (MLKEM.MultiplyNTTs fh gh).map (c * ·) := by
  rw [MultiplyNTTs_eq_ofFn, MultiplyNTTs_eq_ofFn]
  apply Vector.ext; intro i hi
  simp only [Vector.getElem_map, Vector.getElem_ofFn]
  have h0 : 2 * (i/2) < 256 := by agrind
  have h1 : 2 * (i/2) + 1 < 256 := by agrind
  have eq0 : (Vector.map (fun x => c * x) fh)[2 * (i/2)]! = c * fh[2 * (i/2)]! := by
    rw [getElem!_pos (Vector.map _ fh) _ h0, Vector.getElem_map, getElem!_pos fh _ h0]
  have eq1 : (Vector.map (fun x => c * x) fh)[2 * (i/2) + 1]! = c * fh[2 * (i/2) + 1]! := by
    rw [getElem!_pos (Vector.map _ fh) _ h1, Vector.getElem_map, getElem!_pos fh _ h1]
  split
  · unfold baseCaseMultiply0
    rw [eq0, eq1]; ring
  · unfold baseCaseMultiply1
    rw [eq0, eq1]; ring

/-- **D2.4.b** — `MultiplyNTTs` distributes over the right scalar factor:
    `MultiplyNTTs fh (gh.map (c * ·)) = (MultiplyNTTs fh gh).map (c * ·)`.

Informal proof. Symmetric to D2.4.a.  By 128-case extensionality of the
output `Polynomial` (FIPS 203 §4.3.1 Algorithm 11 base-case pairs), reduce to
bilinearity of `BaseCaseMultiply` in its right argument: substitute
`(b₀, b₁) ↦ (c·b₀, c·b₁)` into `(a₀·b₀ + a₁·b₁·γ, a₀·b₁ + a₁·b₀)` (Alg. 12)
and pull `c` out of both components by commutativity and associativity in
`ZMod 3329`, with `γ = ζ^(2 · bitRev 7 i + 1)` and `ζ = 17`.

Case analysis is only on the output coordinate shape (even / odd of each
base-case pair).  Close with `Polynomial`/`Vector` extensionality, `simp`
over `MultiplyNTTs`, `BaseCaseMultiply`, `Polynomial.scalarMul` / `Vector.map`,
and `ring`.

FIPS 203 reference: §4.3.1 Algorithms 11 and 12. -/
theorem MultiplyNTTs_scalarMul_right (c : Zq) (fh gh : Polynomial) :
    MLKEM.MultiplyNTTs fh (gh.map (c * ·))
      = (MLKEM.MultiplyNTTs fh gh).map (c * ·) := by
  rw [MultiplyNTTs_eq_ofFn, MultiplyNTTs_eq_ofFn]
  apply Vector.ext; intro i hi
  simp only [Vector.getElem_map, Vector.getElem_ofFn]
  have h0 : 2 * (i/2) < 256 := by agrind
  have h1 : 2 * (i/2) + 1 < 256 := by agrind
  have eq0 : (Vector.map (fun x => c * x) gh)[2 * (i/2)]! = c * gh[2 * (i/2)]! := by
    rw [getElem!_pos (Vector.map _ gh) _ h0, Vector.getElem_map, getElem!_pos gh _ h0]
  have eq1 : (Vector.map (fun x => c * x) gh)[2 * (i/2) + 1]! = c * gh[2 * (i/2) + 1]! := by
    rw [getElem!_pos (Vector.map _ gh) _ h1, Vector.getElem_map, getElem!_pos gh _ h1]
  split
  · unfold baseCaseMultiply0
    rw [eq0, eq1]; ring
  · unfold baseCaseMultiply1
    rw [eq0, eq1]; ring

/-! ## D2.5 — Vector-level linearity bridges -/

/-- **D2.5.a** — `PolyVector.NTT` distributes over componentwise scalar mul.

    PolyVector.NTT (v.map (Polynomial.scalarMul · c))
      = (PolyVector.NTT v).map (Polynomial.scalarMul · c)

Informal proof: by `Vector.map_map`, reduces to D2.1 fibrewise. -/
theorem PolyVector_NTT_scalarMul_commute {k : MLKEM.K}
    (c : Zq) (v : MLKEM.PolyVector q k) :
    MLKEM.PolyVector.NTT (v.map (fun p => p.map (c * ·)))
      = (MLKEM.PolyVector.NTT v).map (fun p => p.map (c * ·)) := by
  apply Vector.ext; intro i hi
  simp only [MLKEM.PolyVector.NTT, Vector.getElem_map]
  exact NTT_scalarMul c v[i]

/-- **D2.5.b** — `PolyVector.NTTInv` distributes over componentwise scalar mul.

Informal proof. By vector extensionality and the polynomial-level
inverse-NTT linearity (Algorithm 10 Gentleman–Sande butterflies + `128⁻¹`
fixup, both scalar-linear over `ZMod 3329`).  Unfolding the LHS gives
`v.map (fun p => MLKEM.NTTInv (p.map (c * ·)))`; unfolding the RHS gives
`v.map (fun p => (MLKEM.NTTInv p).map (c * ·))`.  By `Vector.ext`, reduces
to the polynomial-level claim at every component index.

That claim is the standard Algorithm 10 scalar-linearity fact: every butterfly
step `(a, b) ↦ (a + b, ζ⁻¹ (a − b))` over `ZMod 3329` is `Zq`-linear, so
`NTTInv (c · f) = c · NTTInv f` follows by induction on layers; the final
`128⁻¹` multiplication commutes with `c · ·` by commutativity of `Zq`.

There is no data-dependent case split: prove pointwise for every vector
component and every coefficient of the resulting polynomial.  Close with
`Vector.ext`, `simp [MLKEM.PolyVector.NTTInv, Vector.map_map]`, then the
polynomial scalar-linearity step (the inverse counterpart of `NTT_scalarMul`).

FIPS 203 reference: §4.3 Algorithm 10. -/
theorem PolyVector_NTTInv_scalarMul_commute {k : MLKEM.K}
    (c : Zq) (v : MLKEM.PolyVector q k) :
    MLKEM.PolyVector.NTTInv (v.map (fun p => p.map (c * ·)))
      = (MLKEM.PolyVector.NTTInv v).map (fun p => p.map (c * ·)) := by
  apply Vector.ext; intro i hi
  simp only [MLKEM.PolyVector.NTTInv, Vector.getElem_map]
  exact NTTInv_scalarMul c v[i]

/-! ## D2.6 — `innerProductNTT` Mont cancellation lemma

This is the key algebraic identity used by `vector_mont_dot_product`.
The impl accumulates `mont_mul`-of-pointwise-products, which introduces
one `Rinv` factor per pair (cancelled by the `· R` factor that `s` carries
in Montgomery form). The spec writes pure `innerProductNTT` without any
`R`/`Rinv` factors.
-/

/-! ## Helpers for D2.6 — additive structure of `(c * ·)` on `Polynomial` -/

/-- The fixed-scalar map `(c * ·)` is additive over polynomial addition. -/
private theorem map_smul_add (c : Zq) (a b : Polynomial) :
    (a + b).map (c * ·) = a.map (c * ·) + b.map (c * ·) := by
  rw [Polynomial.eq_iff]
  intro i hi
  have hmap : ∀ (v : Polynomial), (Vector.map (fun x => c * x) v)[i]! = c * v[i]! := by
    intro v
    rw [getElem!_pos (Vector.map _ v) _ hi, Vector.getElem_map, getElem!_pos v _ hi]
  rw [hmap, Polynomial.getElem!_add, Polynomial.getElem!_add, hmap, hmap]
  ring

/-- `(c * ·)` map sends the zero polynomial to the zero polynomial. -/
private theorem map_smul_zero (c : Zq) :
    (Polynomial.zero : Polynomial).map (c * ·) = Polynomial.zero := by
  rw [Polynomial.eq_iff]
  intro i hi
  have h1 : (Vector.map (fun x => c * x) (Polynomial.zero : Polynomial))[i]!
            = c * (Polynomial.zero : Polynomial)[i]! := by
    rw [getElem!_pos (Vector.map (fun x => c * x) (Polynomial.zero : Polynomial)) _ hi,
        Vector.getElem_map, getElem!_pos (Polynomial.zero : Polynomial) _ hi]
  rw [h1, Polynomial.zero_getElem!, mul_zero]

/-- **D2.6** — Inner product is linear in the left vector argument.

For `v, w : PolyVector q k` and `c : Zq`,

    innerProductNTT (v.map (·.map (c * ·))) w
      = (innerProductNTT v w).map (c * ·)

Informal proof. By induction on the `PolyVector.innerProductNTT` fold and
pointwise polynomial extensionality.  Unfolding the inner product gives
the pure accumulator loop (FIPS 203 §4.3.1 Algorithm 11 driver): start at
`Polynomial.zero`, and for each `i < k` update
`acc := acc + MLKEM.MultiplyNTTs v[i] w[i]`.  Substituting the scaled vector
replaces each `v[i]` by `(v[i]).map (c * ·)`.

Base case: `Polynomial.zero = Polynomial.zero.map (c * ·)` (via `map_smul_zero`).

Inductive step: apply `MultiplyNTTs_scalarMul_left` to the new summand to
move the scalar out of one factor, then use distributivity of the
fixed-scalar map over polynomial addition (`map_smul_add`).

FIPS 203 reference: §4.3.1 Algorithms 11 and 12. -/
theorem innerProductNTT_scalarMul_left {k : MLKEM.K}
    (c : Zq) (v w : MLKEM.PolyVector q k) :
    MLKEM.PolyVector.innerProductNTT (v.map (fun p => p.map (c * ·))) w
      = (MLKEM.PolyVector.innerProductNTT v w).map (c * ·) := by
  obtain ⟨kv, hkv⟩ := k
  simp only [Set.mem_insert_iff, Set.mem_singleton_iff] at hkv
  unfold MLKEM.PolyVector.innerProductNTT
  rcases hkv with rfl | rfl | rfl <;>
  · simp only [Id.run, Aeneas.SRRange.forIn'_eq_forIn'_range', Aeneas.SRRange.size,
               show ∀ (n : Nat), (n - 0 + 1 - 1) / 1 = n from fun _ => by omega,
               List.range', List.forIn'_cons, List.forIn'_nil, pure_bind]
    simp only [pure]
    iterate 4 first | rw [map_smul_add] | skip
    rw [map_smul_zero]
    simp only [MultiplyNTTs_scalarMul_left, Vector.getElem_map]

/-! ### Row-getter for `MulVectorNTT` (foundational helper for D2.6')

Each `MulVectorNTT_get_eq_<k>` (k ∈ {2, 3, 4}) closes the concrete-`k`
shape of the lemma by unrolling the nested `for` loops, unfolding
`MLKEM.PolyVector.set` to expose the underlying `Vector.set` chain
(critical: `PolyVector.set` is its own definition, *not* `Vector.set`,
so the standard `Vector.getElem_set_*` simp lemmas need it stripped),
and `fin_cases` on the row index.  They are hoisted as separate
theorems so the per-`k` heartbeat budget does not accumulate. -/

set_option maxHeartbeats 1500000 in
private theorem MulVectorNTT_get_eq_2
    (A : MLKEM.PolyMatrix q ⟨2, by simp⟩)
    (v : MLKEM.PolyVector q ⟨2, by simp⟩) (i : Fin 2) :
    (A.MulVectorNTT v).get i
      = (List.finRange 2).foldl
          (fun acc j => acc + MultiplyNTTs (A i j) v[j])
          Polynomial.zero := by
  unfold MLKEM.PolyMatrix.MulVectorNTT
  simp only [Id.run, Aeneas.SRRange.forIn'_eq_forIn'_range', Aeneas.SRRange.size,
             show ∀ (n : Nat), (n - 0 + 1 - 1) / 1 = n from fun _ => by omega,
             List.range', List.forIn'_cons, List.forIn'_nil, pure_bind, bind_pure]
  simp only [pure, MLKEM.PolyVector.set]
  fin_cases i <;>
    simp [MLKEM.PolyVector.zero, List.finRange, List.ofFn, Vector.get, Fin.foldr,
          Fin.foldr.loop, List.foldl, zero_add]

set_option maxHeartbeats 3000000 in
private theorem MulVectorNTT_get_eq_3
    (A : MLKEM.PolyMatrix q ⟨3, by simp⟩)
    (v : MLKEM.PolyVector q ⟨3, by simp⟩) (i : Fin 3) :
    (A.MulVectorNTT v).get i
      = (List.finRange 3).foldl
          (fun acc j => acc + MultiplyNTTs (A i j) v[j])
          Polynomial.zero := by
  unfold MLKEM.PolyMatrix.MulVectorNTT
  simp only [Id.run, Aeneas.SRRange.forIn'_eq_forIn'_range', Aeneas.SRRange.size,
             show ∀ (n : Nat), (n - 0 + 1 - 1) / 1 = n from fun _ => by omega,
             List.range', List.forIn'_cons, List.forIn'_nil, pure_bind, bind_pure]
  simp only [pure, MLKEM.PolyVector.set]
  fin_cases i <;>
    simp [MLKEM.PolyVector.zero, List.finRange, List.ofFn, Vector.get, Fin.foldr,
          Fin.foldr.loop, List.foldl, zero_add]

set_option maxHeartbeats 6000000 in
private theorem MulVectorNTT_get_eq_4
    (A : MLKEM.PolyMatrix q ⟨4, by simp⟩)
    (v : MLKEM.PolyVector q ⟨4, by simp⟩) (i : Fin 4) :
    (A.MulVectorNTT v).get i
      = (List.finRange 4).foldl
          (fun acc j => acc + MultiplyNTTs (A i j) v[j])
          Polynomial.zero := by
  unfold MLKEM.PolyMatrix.MulVectorNTT
  simp only [Id.run, Aeneas.SRRange.forIn'_eq_forIn'_range', Aeneas.SRRange.size,
             show ∀ (n : Nat), (n - 0 + 1 - 1) / 1 = n from fun _ => by omega,
             List.range', List.forIn'_cons, List.forIn'_nil, pure_bind, bind_pure]
  simp only [pure, MLKEM.PolyVector.set]
  fin_cases i <;>
    simp [MLKEM.PolyVector.zero, List.finRange, List.ofFn, Vector.get, Fin.foldr,
          Fin.foldr.loop, List.foldl, zero_add]

/-- **Row-getter for `MulVectorNTT`** — collapses the imperative double
`for` loop of `MulVectorNTT` into a pure `foldl` over `List.finRange k`,
projected at the row index.  This is the foundational shape lemma that
sidesteps the `(deterministic) timeout at isDefEq` triggered by the
direct `Vector.set` chain approach.

The proof unrolls the spec's nested `Aeneas.SRRange` for-loops via
`forIn'_eq_forIn'_range'` + `List.forIn'_cons/nil`, unfolds
`MLKEM.PolyVector.set` to expose the underlying `Vector.set` chain
(critical — `PolyVector.set` is *not* `Vector.set` and the standard
`Vector.getElem_set_*` simp lemmas don't apply otherwise), then
`fin_cases i` closes each concrete row index by `simp` with the
`PolyVector.zero` getter (which reduces to `Polynomial.zero`).

The per-`k` work is hoisted into three private helpers so that
the heartbeat budget is not accumulated across the three `K` cases
(a single combined proof exceeds the heartbeat limit). -/
private theorem MulVectorNTT_get_eq_aux
    (kv : ℕ) (hkv : kv = 2 ∨ kv = 3 ∨ kv = 4)
    (A : MLKEM.PolyMatrix q ⟨kv, by rcases hkv with rfl | rfl | rfl <;> simp⟩)
    (v : MLKEM.PolyVector q ⟨kv, by rcases hkv with rfl | rfl | rfl <;> simp⟩)
    (i : Fin kv) :
    (A.MulVectorNTT v).get i
      = (List.finRange kv).foldl
          (fun acc j => acc + MultiplyNTTs (A i j) v[j])
          Polynomial.zero := by
  rcases hkv with rfl | rfl | rfl
  · exact MulVectorNTT_get_eq_2 A v i
  · exact MulVectorNTT_get_eq_3 A v i
  · exact MulVectorNTT_get_eq_4 A v i

theorem MulVectorNTT_get_eq {k : MLKEM.K} (A : MLKEM.PolyMatrix q k)
    (v : MLKEM.PolyVector q k) (i : Fin k) :
    (A.MulVectorNTT v).get i
      = (List.finRange k).foldl
          (fun acc j => acc + MultiplyNTTs (A i j) v[j])
          Polynomial.zero := by
  obtain ⟨kv, hkv⟩ := k
  simp only [Set.mem_insert_iff, Set.mem_singleton_iff] at hkv
  exact MulVectorNTT_get_eq_aux kv hkv A v i

/-- Generic helper: distribute an outer `(c * ·)`-map through a foldl
when each step is already in `acc + (g j).map (c * ·)` form.  Used
by `MulVectorNTT_scalarMul_right` after the per-step body has been
normalised by `MultiplyNTTs_scalarMul_right`. -/
private theorem foldl_map_smul_distrib {α : Type*}
    (c : Zq) (f : Polynomial → α → Polynomial)
    (g : α → Polynomial)
    (l : List α) (acc : Polynomial)
    (hbody : ∀ a b, f a b = a + (g b).map (c * ·)) :
    l.foldl f (acc.map (c * ·))
      = (l.foldl (fun a b => a + g b) acc).map (c * ·) := by
  induction l generalizing acc with
  | nil => rfl
  | cons b l ih =>
    simp only [List.foldl_cons, hbody, ← map_smul_add]
    exact ih _

/-- **D2.6'** — Matrix-vector NTT product is linear in the *vector* argument.

For `A : PolyMatrix q k` and `v : PolyVector q k`, scaling each entry of `v`
by `(c * ·)` corresponds (per output coefficient) to scaling each output
entry of `MulVectorNTT A v` by `(c * ·)`:

    MulVectorNTT A (v.map (·.map (c * ·)))
      = (MulVectorNTT A v).map (·.map (c * ·))

This is the matrix-vector analogue of `innerProductNTT_scalarMul_left`
(D2.6): each row of `MulVectorNTT A v` is exactly the inner product of the
row of `A` with `v`, so D2.6's logic applies row-by-row.

Informal proof. Case-split on `k ∈ {2, 3, 4}`.  Unroll both the outer
`for hi: i in [0:k]` (row index) and the inner `for hj: j in [0:k]` (column
index) using
`Aeneas.SRRange.forIn'_eq_forIn'_range'` and `List.forIn'_cons/nil`.  The
result is a fixed sequence of `Vector.set` operations on `PolyVector.zero`.
Use `Vector.ext` on the output row index, drive each `Vector.getElem` through
the `set`-chain via `Vector.getElem_set` + `Nat`-decide of index inequalities,
and reduce both sides to a sum of `MultiplyNTTs A[i,j] v[j]`.  Then apply
`MultiplyNTTs_scalarMul_right` (D2.4.b) and `map_smul_add` to push the
`.map (c * ·)` outside each summand.

Mechanisation. We use the foundational row-getter `MulVectorNTT_get_eq`
(above) to project each row of `MulVectorNTT` to a `List.finRange`-foldl
sum of `MultiplyNTTs` terms; then `MultiplyNTTs_scalarMul_right`
distributes `(c * ·)` through each summand and `map_smul_add` /
`map_smul_zero` collect the per-row maps. -/
theorem MulVectorNTT_scalarMul_right {k : MLKEM.K} (c : Zq)
    (A : MLKEM.PolyMatrix q k) (v : MLKEM.PolyVector q k) :
    MLKEM.PolyMatrix.MulVectorNTT A (v.map (fun p => p.map (c * ·)))
      = (MLKEM.PolyMatrix.MulVectorNTT A v).map (fun p => p.map (c * ·)) := by
  apply Vector.ext
  intro i hi
  have hL : (MLKEM.PolyMatrix.MulVectorNTT A
                (v.map (fun p => p.map (c * ·))))[i]
            = (A.MulVectorNTT (v.map (fun p => p.map (c * ·)))).get ⟨i, hi⟩ := rfl
  have hR : ((MLKEM.PolyMatrix.MulVectorNTT A v).map
                (fun p => p.map (c * ·)))[i]
            = ((A.MulVectorNTT v).get ⟨i, hi⟩).map (c * ·) := by
    rw [Vector.getElem_map]; rfl
  rw [hL, hR, MulVectorNTT_get_eq, MulVectorNTT_get_eq]
  conv_lhs => rw [← map_smul_zero c]
  apply foldl_map_smul_distrib c
    (g := fun j => MultiplyNTTs (A ⟨i, hi⟩ j) v[j])
  intro a j
  rw [show (v.map (fun p => p.map (c * ·)))[j] = v[j].map (c * ·) by simp,
      MultiplyNTTs_scalarMul_right]

end Symcrust.Properties.MLKEM.Bridges
