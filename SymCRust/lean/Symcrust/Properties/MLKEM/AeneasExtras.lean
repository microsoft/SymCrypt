/-
# `AeneasExtras.lean` — small, general-purpose simp lemmas

A collection of general-purpose helper simp lemmas.

Scope discipline: every helper here must be statable without mentioning
MLKEM, NTT, `Zq`, `3329`, `65536`, `Vector 256`, or any ML-KEM-specific
identifier. If a helper needs those, it lives in `Basic.lean` (or a
per-area file), not here.
-/

import Symcrust.Code
-- Bring in the surrounding Aeneas namespaces so the lemmas below can
-- reference `Slice`, etc. unqualified.

open Aeneas Aeneas.Std

namespace Symcrust.Properties.MLKEM.AeneasExtras

/-! ## 1. Slice element access — `[i]'h` to total `val[i]'h_list`

The upstream `Slice.getElem_Nat_eq` already covers the total case
(`v[i] = v.val[i]` when `i < v.val.length`) and is `@[simp]`. The
partial-form lemma below is an *opt-in* `rw` target — deliberately not
`@[simp]`, since rewriting total `s[i]'h` → partial `s.val[i]!` would
propagate `!` into every downstream goal — for the rare proof that needs
`[..]!` form before a downstream `!`-shaped lemma. -/

/-- Opt-in conversion `s[i]'h → s.val[i]!` (not `@[simp]`). Use
`Slice.getElem_Nat_eq` (upstream, `@[simp]`) for the total direction. -/
theorem Aeneas.Std.Slice.getElem_eq_val_getElem! {α : Type u} [Inhabited α]
    (s : Slice α) (i : Nat) (h : i < s.length) :
    s[i]'h = s.val[i]! := by
  rw [Slice.Inhabited_getElem_eq_getElem! s i h]
  exact Slice.getElem!_Nat_eq s i

/-! ## 2. `SRRange.size` for unit-step constant-length ranges

`SRRange.size` unfolds to `(stop - start + step - 1) / step`. For
`start = a`, `stop = a + len`, `step = 1`, this is
`(a + len - a + 1 - 1) / 1 = len` — a fact otherwise spelled out by
hand once per constant, e.g.:

    show ∀ a, (a + 128 - a + 1 - 1) / 1 = 128 from fun a => by omega
    show ∀ a, (a + 64  - a + 1 - 1) / 1 = 64  from fun a => by omega
    …

One general simp lemma replaces all seven, twice (`ntt_eq`,
`invNtt_eq`). -/

@[simp]
theorem size_step_one_const_len (a len : Nat) :
    (a + len - a + 1 - 1) / 1 = len := by
  omega

end Symcrust.Properties.MLKEM.AeneasExtras
