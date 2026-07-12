#!/usr/bin/env python3
"""
prune-external-template.py — post-extraction pruner for FunsExternal_Template.lean.

Runs after `aeneas` has emitted the template. Scans `@[rust_fun "..."]`
declarations across the **Intrinsics binding closure** (Lean files that
*should* be the canonical bindings for given Rust paths) and removes
matching declarations from `FunsExternal_Template.lean`.

Effect (A2 mechanism — see campaign plan):

  * The template no longer carries declarations for paths bound by
    `lean/Intrinsics/Axioms/**.lean`, nor for paths bound by the
    algorithm-level composite-shim files at
    `lean/Symcrust/Properties/<Alg>/Intrinsics/**.lean`.
  * Aeneas's "use this binding" lookup still finds the rust_fun decl
    in the imported `Intrinsics.*` files when extracting downstream
    proofs — same dispatch path as `Aeneas.Std`.
  * Downstream `FunsExternal.lean` (the hand-edited derivative) is
    NOT touched by this script. The existing `extract-postprocess`
    rule copies `FunsExternal_Template.lean` to `FunsExternal.lean`
    only when the latter is absent (first extraction); on subsequent
    runs the user can diff to reconcile.

Constants in this script: NONE. The list of Rust paths to prune is
derived live from the @[rust_fun "..."] decls in the Intrinsics
closure. The trust ledger is the Lean source.

Safety rails:

  * CI-friendly exit codes:
       0  on success (template was pruned cleanly).
       1  on any silicon `core::core_arch::*` path remaining in the
          pruned template that is not bound — surfaces "newly
          unhandled" intrinsic on every extraction.
       2  on hard error (missing inputs, parse failure).
  * `--check` mode runs the prune in-memory and exits non-zero if the
    output would differ from the input — useful as a CI invariant
    after the campaign claims everything is bound.

Usage:
    python3 scripts/prune-external-template.py
    python3 scripts/prune-external-template.py --subdir Symcrust/CodeAES
    python3 scripts/prune-external-template.py --check
    python3 scripts/prune-external-template.py --dry-run --verbose
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Filesystem roots scanned for binding declarations.
BIND_ROOTS = [
    REPO_ROOT / "lean" / "Intrinsics",
    REPO_ROOT / "lean" / "Symcrust" / "Properties",
]

# Regex catches @[rust_fun "..."] / @[rust_type "..."] across whitespace/newlines.
RE_RUST_FUN = re.compile(r'@\[rust_fun\s+"([^"]+)"')
RE_RUST_TYPE = re.compile(r'@\[rust_type\s+"([^"]+)"')
# Either binding attribute (funs template binds @[rust_fun]; types template
# binds @[rust_type] carrier types such as `core::core_arch::x86::__m128i`).
RE_BINDING = re.compile(r'@\[rust_(?:fun|type)\s+"([^"]+)"')

# Silicon intrinsic gate — the CI invariant looks for these in the pruned output.
RE_SILICON_PATH = re.compile(r"^core::core_arch::")


def collect_bound_paths(verbose: bool) -> dict[str, list[Path]]:
    """Walk BIND_ROOTS, return path -> list of files that bind it."""
    bound: dict[str, list[Path]] = {}
    for root in BIND_ROOTS:
        if not root.exists():
            continue
        for f in root.rglob("*.lean"):
            try:
                text = f.read_text()
            except Exception as e:
                print(f"WARN: could not read {f}: {e}", file=sys.stderr)
                continue
            for m in RE_BINDING.finditer(text):
                path = m.group(1)
                bound.setdefault(path, []).append(f)
    if verbose:
        for path, files in sorted(bound.items()):
            print(f"  bound: {path}")
            for f in files:
                print(f"      from {f.relative_to(REPO_ROOT)}")
    return bound


def split_blocks(text: str) -> tuple[list[str], list[str]]:
    """Split into (preamble, [block, ...]).

    Preamble = leading lines up to the first blank line containing only the
    file header (imports, set_options, open). Each subsequent block is one
    Aeneas-emitted declaration (optionally with leading docstring), separated
    by blank lines. Within a block, blank lines are NOT expected (Aeneas
    does not emit them mid-declaration), so blank-line split is safe."""
    chunks: list[str] = []
    cur: list[str] = []
    for line in text.splitlines():
        if line.strip() == "":
            if cur:
                chunks.append("\n".join(cur))
                cur = []
            else:
                # Blank line at preamble boundary — keep as separator.
                if not chunks:
                    chunks.append("")
        else:
            cur.append(line.rstrip())
    if cur:
        chunks.append("\n".join(cur))

    # The first non-empty chunk is the preamble (imports + open + set_options).
    # We DETECT the preamble as the leading chunk that contains no `@[rust_fun]`
    # declarations and has Lean keywords like `import` / `open` / `set_option`.
    preamble_chunks: list[str] = []
    decl_chunks: list[str] = []
    for ch in chunks:
        if not preamble_chunks or RE_RUST_FUN.search(ch) is None and (
            ch == "" or any(k in ch for k in ("import ", "open ", "set_option"))
        ) and not decl_chunks:
            preamble_chunks.append(ch)
        else:
            decl_chunks.append(ch)
    return preamble_chunks, decl_chunks


def block_path(block: str) -> str | None:
    m = RE_BINDING.search(block)
    return m.group(1) if m else None


# Sentinel comment marking the imports we inject. Lets us avoid duplicate
# insertion when the pruner is run repeatedly on the same template.
INJECT_SENTINEL = "-- @injected by scripts/prune-external-template.py"


def axioms_path_to_properties_module(p: Path) -> str | None:
    """Map `lean/Intrinsics/Axioms/<Arch>/<Ext>.lean` to the public
    silicon-axiom module `Intrinsics.Axioms.<Arch>.<Ext>` that
    `FunsExternal.lean` should import directly.

    Historically this routed through a `Intrinsics.Properties.<Arch>.<Ext>`
    façade so that a Phase-2 axiom→theorem downgrade in the Properties
    file would be picked up automatically.  That indirection was dropped
    when the per-shim `@[step] theorem`s for `verify.intrinsics.*` were
    inlined into the Properties files (which now `import Symcrust.Code.Funs`,
    creating a cycle with FunsExternal if it imported them).  The new
    m-axiom-spec-pairs convention adds the silicon-`.spec` `@[step] axiom`
    siblings INSIDE the Axioms file alongside the typing axiom, so
    consumers like FunsExternal pick those up directly with no façade."""
    try:
        rel = p.relative_to(REPO_ROOT / "lean")
    except ValueError:
        return None
    parts = rel.with_suffix("").parts
    # Expected shape: ("Intrinsics", "Axioms", "<Arch>", "<Ext>") for per-ISA
    # axiom files, or ("Intrinsics", "Axioms", "<Ext>") for arch-generic ones
    # such as `Core.lean` (`core::intrinsics::*`).
    if len(parts) < 3 or parts[0] != "Intrinsics" or parts[1] != "Axioms":
        return None
    return "Intrinsics.Axioms." + ".".join(parts[2:])


def file_to_module(p: Path) -> str | None:
    """Map any binding file `lean/<A>/<B>/<C>.lean` to its dotted Lean module
    `<A>.<B>.<C>` (e.g. `lean/Intrinsics/Simd.lean` -> `Intrinsics.Simd`).

    Used by the TypesExternal pruner, whose carrier bindings (e.g.
    `core::core_arch::x86::__m128i`) live in leaf `Intrinsics.*` modules (which
    import only `Aeneas`, so `Code/TypesExternal` can import them cycle-free),
    NOT under `Intrinsics/Axioms/`."""
    try:
        rel = p.relative_to(REPO_ROOT / "lean")
    except ValueError:
        return None
    return ".".join(rel.with_suffix("").parts)


def imports_for_used_bindings(bound: dict[str, list[Path]], used_paths: list[str],
                              module_of=axioms_path_to_properties_module) -> list[str]:
    """Return the sorted list of Lean modules whose binding file supplied at
    least one binding in `used_paths`, mapped via `module_of` (the per-ISA
    Axioms module for funs; the leaf `Intrinsics.*` module for types)."""
    modules: set[str] = set()
    for path in used_paths:
        for f in bound.get(path, []):
            m = module_of(f)
            if m is not None:
                modules.add(m)
    return sorted(modules)


def inject_imports(preamble_text: str, imports: list[str]) -> str:
    """Inject Intrinsics façade `import` lines into the preamble.

    If the sentinel is already present, replace the existing injected block
    in place. Otherwise insert directly after the last `import` line."""
    inject_block = (
        f"\n{INJECT_SENTINEL} (start)\n"
        + "\n".join(f"import {m}" for m in imports)
        + f"\n{INJECT_SENTINEL} (end)\n"
    )
    if INJECT_SENTINEL + " (start)" in preamble_text:
        # Replace existing block.
        start = preamble_text.index(INJECT_SENTINEL + " (start)")
        # Find the matching (end) line and consume up to and incl. its trailing newline.
        end_marker = INJECT_SENTINEL + " (end)"
        end = preamble_text.index(end_marker, start) + len(end_marker)
        # Consume the rest of that line.
        line_end = preamble_text.find("\n", end)
        if line_end == -1:
            line_end = len(preamble_text)
        # Also consume the leading newline before "(start)" so we don't accumulate blanks.
        prev_nl = preamble_text.rfind("\n", 0, start)
        if prev_nl == -1:
            prev_nl = 0
        return preamble_text[:prev_nl] + inject_block.rstrip("\n") + preamble_text[line_end:]
    # Fresh insert: place after the last `import ` line of the preamble.
    lines = preamble_text.splitlines()
    last_import = -1
    for i, ln in enumerate(lines):
        if ln.startswith("import "):
            last_import = i
    if last_import < 0:
        # No `import` found — append at end (unusual; preamble should have imports).
        return preamble_text.rstrip("\n") + inject_block
    head = lines[: last_import + 1]
    tail = lines[last_import + 1 :]
    return "\n".join(head) + inject_block + "\n".join(tail)


def prune(text: str, bound: dict[str, list[Path]],
          module_of=axioms_path_to_properties_module) -> tuple[str, list[str], list[str], list[str]]:
    """Return (new_text, pruned_paths, remaining_unbound_silicon_paths, imports_used)."""
    preamble, decls = split_blocks(text)
    pruned: list[str] = []
    kept: list[str] = []
    unbound_silicon: list[str] = []
    for block in decls:
        path = block_path(block)
        if path is None:
            kept.append(block)
            continue
        if path in bound:
            pruned.append(path)
        else:
            kept.append(block)
            if RE_SILICON_PATH.match(path):
                unbound_silicon.append(path)
    imports = imports_for_used_bindings(bound, pruned, module_of)
    # Reassemble: preamble blocks joined by single blank lines, then a blank
    # line separator, then declarations joined by blank lines.
    pre = "\n\n".join(preamble).rstrip()
    if imports:
        pre = inject_imports(pre, imports)
    body = "\n\n".join(kept)
    new_text = (pre + "\n\n" + body).lstrip("\n") + "\n"
    return new_text, pruned, unbound_silicon, imports


def process_template(template: Path, bound: dict[str, list[Path]], module_of, args) -> tuple[bool, bool, bool]:
    """Prune one *_Template.lean. Returns (found, would_change, has_unbound_silicon)."""
    if not template.exists():
        return (False, False, False)
    original = template.read_text()
    new_text, pruned, unbound, imports = prune(original, bound, module_of)
    changed = new_text != original
    rel = template.relative_to(REPO_ROOT)
    print(f"[prune] template       : {rel}")
    print(f"[prune] entries pruned : {len(pruned)}")
    print(f"[prune] imports injected: {len(imports)}")
    if args.verbose and imports:
        for m in imports:
            print(f"          import {m}")
    if args.verbose:
        for p in pruned:
            print(f"          -> {p}")
    if unbound:
        print(f"[prune] WARN: {len(unbound)} silicon path(s) remain UNBOUND in {rel.name}:")
        for p in sorted(set(unbound)):
            print(f"          ?? {p}")
    else:
        print(f"[prune] {rel.name}: all silicon (core::core_arch::*) paths are bound")
    if not args.check and not args.dry_run:
        if changed:
            template.write_text(new_text)
            print(f"[prune] wrote pruned {rel.name} ({len(pruned)} entries removed)")
        else:
            print(f"[prune] {rel.name}: no change (already pruned or no matching bindings)")
    return (True, changed, bool(unbound))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--subdir", default="Symcrust/Code",
                    help="Subdirectory under lean/ holding the *External_Template.lean files")
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if pruning would change a file")
    ap.add_argument("--dry-run", action="store_true",
                    help="report only, do not write")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    d = REPO_ROOT / "lean" / args.subdir
    funs_template = d / "FunsExternal_Template.lean"
    if not funs_template.exists():
        print(f"ERROR: template not found: {funs_template}", file=sys.stderr)
        return 2

    bound = collect_bound_paths(verbose=args.verbose)
    if not bound:
        print("WARN: no @[rust_fun]/@[rust_type] bindings found under bind roots:", file=sys.stderr)
        for r in BIND_ROOTS:
            print(f"  {r}", file=sys.stderr)
    print(f"[prune] bindings found : {len(bound)}")

    any_changed = False
    any_unbound = False
    # FunsExternal: import target is the per-ISA `Intrinsics.Axioms.<Arch>.<Ext>`
    # module (routing through Properties would close a cycle — see
    # `axioms_path_to_properties_module`).
    _, ch, ub = process_template(funs_template, bound, axioms_path_to_properties_module, args)
    any_changed = any_changed or ch
    any_unbound = any_unbound or ub
    # TypesExternal: carrier bindings (`__m128i`, …) live in leaf `Intrinsics.*`
    # modules, mapped verbatim by `file_to_module`.
    types_template = d / "TypesExternal_Template.lean"
    _, ch, ub = process_template(types_template, bound, file_to_module, args)
    any_changed = any_changed or ch
    any_unbound = any_unbound or ub

    if args.check:
        if any_changed:
            print("[prune] --check: a template would change (NOT in steady state)", file=sys.stderr)
            return 1
        if any_unbound:
            print("[prune] --check: unbound silicon path(s) present", file=sys.stderr)
            return 1
        return 0
    if args.dry_run:
        print("[prune] --dry-run: not writing")
        return 1 if any_unbound else 0
    return 1 if any_unbound else 0


if __name__ == "__main__":
    sys.exit(main())
