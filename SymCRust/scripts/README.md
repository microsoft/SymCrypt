# SymCRust verification scripts

Tooling that sits between the Charon → Aeneas extraction pipeline and the
hand-authored Lean proofs under `lean/Symcrust/Properties/`. All three
scripts below are invoked from `make extract-postprocess` in
`SymCRust/Makefile`; see `lean/Symcrust/Code/EXTRACTION.md` for the
canonical reproduction recipe.

## `prune-external-template.py`

Post-processor for the auto-generated `FunsExternal_Template.lean`. Two jobs:

1. **Prune silicon stubs.** Removes every `@[rust_fun "core::core_arch::…"]`
   axiom whose Rust path is already bound by a hand-authored axiom or step
   theorem under `lean/Symcrust/Properties/**`. Aeneas emits these stubs
   because it does not know about silicon intrinsics; our binding files
   take over.
2. **Inject façade imports.** For each architecture whose binding files
   supplied at least one pruned path, injects
   `import Symcrust.Properties.Intrinsics.<Arch>.<Ext>` into the Template's
   preamble. The block is delimited by a sentinel comment
   (`-- @injected by scripts/prune-external-template.py`) so re-runs replace
   in place.

Usage:

```bash
python3 scripts/prune-external-template.py            # write mode (used by Makefile)
python3 scripts/prune-external-template.py --check    # CI: exit 1 on unbound silicon
python3 scripts/prune-external-template.py --dry-run --verbose
```

## `disambiguate-trait-fields.py`

Repairs a known Aeneas extractor regression where a trait monomorphised
over multiple type parameters emits two `structure` fields with the same
name in the generated Lean. The script rewrites the duplicates to
unique field names and patches the corresponding constructor calls.

## `strip-iterator-zip-rev.py`

Strips `zip := …` and `rev := …` field clauses from
`core.iter.traits.iterator.Iterator` impl records in extracted Lean files.
Charon emits 6 fields (`next`, `step_by`, `zip`, `enumerate`, `take`,
`rev`) but the pinned `Aeneas.Std.Core.Iter` structure declares only 4;
this script removes the extras so the Lean elaborator accepts the
extraction.
