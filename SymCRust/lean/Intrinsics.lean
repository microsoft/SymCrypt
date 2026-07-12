/-!
# `Intrinsics` — verified models of hardware intrinsics

This Lean root namespace holds the per-(architecture, ISA-extension)
step specs (theorems + axioms) for every hardware intrinsic reachable
from a verified SymCRust function. See `SymCRust/lean/Intrinsics/INTRINSICS.md` for
the methodology and trust ledger.

Aeneas extraction is NOT modular. The intrinsic shims under
`src/verify/intrinsics/**` are extracted as transitive dependencies of
whichever primitive(s) the extraction covers (via `make extract`);
their defs land in the
same `Symcrust.Code.Funs` the primitives consume. There is therefore
NO separate `Intrinsics.Code` namespace.

Strict layering rule: this tree imports only `Aeneas.*` and
`Symcrust.Code.*` (the auto-generated prefix). It never imports
`Symcrust.Properties.*` or any other hand-authored Symcrust module.
Per-extension step theorems land in
`Intrinsics.Properties.<Arch>.<Ext>`; trust-boundary axioms land in
`Intrinsics.Axioms.<Arch>.<Ext>`.

This file is currently a namespace landing pad; top-level imports will
be added when the first per-extension file is authored.
-/

namespace Intrinsics
end Intrinsics
