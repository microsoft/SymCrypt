import Aeneas

/-! # Deterministic `get_target` spec (local override)

`Aeneas.Std.get_target` is an Aeneas builtin returning the compilation's target
as a `Str`.  Aeneas ships it with the vacuous spec `⦃ _ => True ⦄`, which is too
weak for target-correlated reasoning: a Rust compilation has **exactly one**
(global) target (`rustc --target`; `cfg!(target_arch=…)` is a compile-time
constant), so `get_target` returns the same value at every call site.

We model that value as a single fixed-but-arbitrary constant `theTarget` and give
`get_target` the deterministic post `r = theTarget`.  Because `step` does not
prefer the stronger of two registered `@[step]` specs for the same function, we
**deactivate** the Aeneas spec with `attribute [-step]` (global, persists through
imports) so `step` / `step*` pick ours.

> **Upstreaming.** This exact change is filed against Aeneas (branch
> `gcm-on-verify`); once it lands upstream, delete this file and drop the
> `import` of it (the Aeneas spec will then already post `r = theTarget`). -/

open Aeneas Aeneas.Std Result

namespace symcrust

/-- The build's compile-time target — an arbitrary fixed value.  Bodyless, hence
    genuinely opaque: proofs cannot observe which target it is, so they hold for
    whichever extracted target this build is. -/
axiom theTarget : Std.Str

/- Deactivate Aeneas's vacuous `get_target` spec (`⦃ _ => True ⦄`) in favour of
   the deterministic one below.  The deactivation is global and propagates to
   every importer, so `step`/`step*` pick `symcrust.get_target.spec`. -/
attribute [-step] Aeneas.Std.get_target.spec

/-- `get_target` deterministically returns *the* build target. -/
@[step]
axiom get_target.spec :
    Aeneas.Std.get_target ⦃ (r : Std.Str) => r = theTarget ⦄

end symcrust
