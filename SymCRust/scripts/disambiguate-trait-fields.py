#!/usr/bin/env python3
"""
disambiguate-trait-fields.py — post-extraction repair for Aeneas
trait-field duplicate-name regressions in Lean output.

Background (see AENEAS-BLOCKERS §3.I):
  At the current Aeneas pin (2026-05-30), the extractor occasionally
  emits two `structure` fields with the same name when a trait is
  monomorphised over multiple type parameters, e.g.::

      structure sha2.sha2_impl.Sha2Core
        (Self_Words : Type) (Self_Buffer : Type) ... where
        ...
        corecloneCloneInst : core.clone.Clone Self_Words
        corecloneCloneInst : core.clone.Clone Self_Buffer
        ...

  Lean rejects this with::

      error: Field 'corecloneCloneInst' has already been declared

Repair strategy:
  1. Parse every `structure` declaration in Types.lean and detect
     duplicate field names within the same block.
  2. The first occurrence keeps the base name. Each subsequent
     duplicate is suffixed with a token derived from a `Self_X`
     identifier that appears in this field's type but not in the
     previous ones (e.g. `Self_Buffer` → suffix `Buffer`).
  3. Rewrite the duplicate's declaration in Types.lean.
  4. In Funs.lean, for each instance literal of the affected
     structure (matching `: <FullStructName> ... := { ... }`),
     rename the N-th in-order occurrence of the duplicate field
     initialiser within that block.
  5. For method-call sites of the form
     `<Inst>.<old_field>.<method> <arg>`, apply a best-effort
     rename: if the leaf identifier of `<arg>` contains the
     disambiguating suffix as a case-insensitive substring, rename
     to the suffixed variant; otherwise leave the base name.

Abort conditions (with clear diagnostics):
  - A duplicate field cannot be disambiguated (no distinguishing
    `Self_X` token).
  - A method-call site would match multiple candidate suffixes.

The script is idempotent: a clean Lean tree is a no-op.

Usage (run from SymCRust/):
    python3 scripts/disambiguate-trait-fields.py
    python3 scripts/disambiguate-trait-fields.py --subdir Symcrust/Code
    python3 scripts/disambiguate-trait-fields.py --check    # dry-run
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

STRUCT_HEADER_RE = re.compile(r"^structure\s+(\S+)\b")
FIELD_DECL_RE = re.compile(r"^(\s+)([A-Za-z_][\w']*)\s*:\s*(.+?)\s*$")
SELF_TOK_RE = re.compile(r"\bSelf_(\w+)\b")


def parse_structures(
    lines: List[str],
) -> List[Tuple[str, List[Tuple[int, str, str]]]]:
    """Return [(struct_full_name, [(line_idx, field_name, field_type), ...]), ...]."""
    out: List[Tuple[str, List[Tuple[int, str, str]]]] = []
    n = len(lines)
    i = 0
    while i < n:
        m = STRUCT_HEADER_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        where_i = i
        while where_i < n and "where" not in lines[where_i]:
            where_i += 1
        if where_i == n:
            i += 1
            continue
        fields: List[Tuple[int, str, str]] = []
        field_indent: str | None = None
        k = where_i + 1
        while k < n:
            line = lines[k]
            stripped = line.rstrip("\n")
            if not stripped.strip():
                kk = k + 1
                while kk < n and not lines[kk].strip():
                    kk += 1
                if kk == n or not lines[kk].startswith(" "):
                    break
                k = kk
                continue
            if not line.startswith(" "):
                break
            fm = FIELD_DECL_RE.match(line)
            if fm is None:
                k += 1
                continue
            indent, fname, ftype = fm.group(1), fm.group(2), fm.group(3)
            if field_indent is None:
                field_indent = indent
            if indent != field_indent:
                k += 1
                continue
            fields.append((k, fname, ftype))
            k += 1
        out.append((name, fields))
        i = k
    return out


def derive_suffix(prev_types: List[str], this_type: str) -> str | None:
    this_toks = set(SELF_TOK_RE.findall(this_type))
    prev_toks: set[str] = set()
    for t in prev_types:
        prev_toks |= set(SELF_TOK_RE.findall(t))
    diff = sorted(this_toks - prev_toks)
    if len(diff) == 1:
        return diff[0]
    if not diff and len(this_toks) == 1:
        return next(iter(this_toks))
    return None


RenamePlan = Dict[str, List[Tuple[int, str, str]]]  # struct -> [(line, old, new), ...]


def compute_renames(
    structures: List[Tuple[str, List[Tuple[int, str, str]]]],
) -> RenamePlan:
    plan: RenamePlan = {}
    for sname, fields in structures:
        by_name: Dict[str, List[Tuple[int, str]]] = {}
        for (lidx, fname, ftype) in fields:
            by_name.setdefault(fname, []).append((lidx, ftype))
        for fname, occs in by_name.items():
            if len(occs) < 2:
                continue
            renames: List[Tuple[int, str, str]] = []
            seen_types = [occs[0][1]]
            for (lidx, ftype) in occs[1:]:
                suffix = derive_suffix(seen_types, ftype)
                if suffix is None:
                    sys.stderr.write(
                        f"[disambiguate-trait-fields] ERROR: cannot derive "
                        f"disambiguating suffix for duplicate field "
                        f"'{fname}' in structure '{sname}'.\n"
                        f"  this type:   {ftype!r}\n"
                        f"  prior types: {seen_types!r}\n"
                    )
                    sys.exit(2)
                renames.append((lidx, fname, fname + suffix))
                seen_types.append(ftype)
            plan.setdefault(sname, []).extend(renames)
    return plan


def apply_types_renames(lines: List[str], plan: RenamePlan) -> int:
    n = 0
    for renames in plan.values():
        for (lidx, old, new) in renames:
            line = lines[lidx]
            new_line = re.sub(
                rf"^(\s+){re.escape(old)}(\s*:\s)",
                rf"\g<1>{new}\g<2>",
                line,
            )
            if new_line == line:
                sys.stderr.write(
                    f"[disambiguate-trait-fields] ERROR: failed to rewrite "
                    f"field '{old}' at Types.lean line {lidx + 1}\n"
                )
                sys.exit(2)
            lines[lidx] = new_line
            n += 1
    return n


def apply_funs_renames(lines: List[str], plan: RenamePlan) -> Tuple[int, int]:
    """Returns (instance-literal renames, method-call renames)."""
    n_inst = 0
    n_call = 0
    for sname, renames in plan.items():
        # For each colliding old name, the list of new names (occurrences 2..)
        # in declaration order.
        by_old: Dict[str, List[str]] = {}
        for (_lidx, old, new) in sorted(renames, key=lambda r: r[0]):
            by_old.setdefault(old, []).append(new)
        if not by_old:
            continue

        # --- Instance-literal rewrites ----------------------------------
        struct_re = re.compile(rf":\s*{re.escape(sname)}\b")
        olds_alt = "|".join(re.escape(o) for o in by_old)
        field_init_re = re.compile(rf"^(\s+)({olds_alt})(\s*:=)")

        i = 0
        L = len(lines)
        while i < L:
            if not struct_re.search(lines[i]):
                i += 1
                continue
            # Find the next "{" that opens the instance literal body.
            j = i
            while j < L and "{" not in lines[j]:
                j += 1
            if j == L:
                i += 1
                continue
            depth = 0
            start = j
            counters: Dict[str, int] = {old: 0 for old in by_old}
            while j < L:
                depth += lines[j].count("{") - lines[j].count("}")
                m = field_init_re.match(lines[j])
                if m:
                    old = m.group(2)
                    idx = counters[old]
                    if idx >= 1:
                        new = by_old[old][idx - 1]
                        lines[j] = re.sub(
                            rf"^(\s+){re.escape(old)}(\s*:=)",
                            rf"\g<1>{new}\g<2>",
                            lines[j],
                        )
                        n_inst += 1
                    counters[old] += 1
                if depth <= 0 and j > start:
                    break
                j += 1
            i = j + 1

        # --- Method-call rewrites (best effort) -------------------------
        # Pattern: <Inst>.<old_field>.<method> <arg>
        # where <arg> is a single token (possibly dotted).
        for old, new_list in by_old.items():
            # Suffixes from the new names (e.g. "Buffer", "Counter", ...)
            suffixes = [new[len(old):] for new in new_list]
            call_re = re.compile(
                rf"\b([A-Za-z_]\w*)\.({re.escape(old)})\.([A-Za-z_]\w*)\b"
                rf"(\s+)([A-Za-z_][\w.]*)"
            )
            for li, line in enumerate(lines):
                def _sub(m: re.Match) -> str:
                    inst, _old, method, ws, arg = m.groups()
                    leaf = arg.rsplit(".", 1)[-1].lower()
                    matches = [
                        (suf, new)
                        for suf, new in zip(suffixes, new_list)
                        if suf and suf.lower() in leaf
                    ]
                    if len(matches) > 1:
                        sys.stderr.write(
                            f"[disambiguate-trait-fields] ERROR: ambiguous "
                            f"method-call rename at Funs.lean line {li + 1}: "
                            f"argument {arg!r} matches multiple suffixes "
                            f"{[s for s, _ in matches]}\n"
                        )
                        sys.exit(2)
                    if not matches:
                        return m.group(0)  # leave base name (first occurrence)
                    nonlocal n_call
                    n_call += 1
                    return f"{inst}.{matches[0][1]}.{method}{ws}{arg}"

                new_line = call_re.sub(_sub, line)
                if new_line != line:
                    lines[li] = new_line
    return n_inst, n_call


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument(
        "--subdir",
        default="Symcrust/Code",
        help="Lean subdirectory under lean/ holding Types.lean and Funs.lean",
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help="report renames without modifying files (exit 1 if changes pending)",
    )
    args = ap.parse_args()

    base = Path("lean") / args.subdir
    types_path = base / "Types.lean"
    funs_path = base / "Funs.lean"
    if not types_path.exists():
        print(
            f"[disambiguate-trait-fields] {types_path} not found; nothing to do."
        )
        return 0

    types_lines = types_path.read_text().splitlines(keepends=True)
    structures = parse_structures(types_lines)
    plan = compute_renames(structures)

    if not plan:
        print("[disambiguate-trait-fields] no duplicate trait fields found.")
        return 0

    total = sum(len(r) for r in plan.values())
    print(
        f"[disambiguate-trait-fields] {total} field rename(s) across "
        f"{len(plan)} structure(s):"
    )
    for sname, renames in plan.items():
        for (lidx, old, new) in renames:
            print(f"    {sname} @ Types.lean:{lidx + 1}: {old} -> {new}")

    if args.check:
        return 1

    n_types = apply_types_renames(types_lines, plan)
    types_path.write_text("".join(types_lines))
    print(
        f"[disambiguate-trait-fields] wrote {n_types} rename(s) to {types_path}"
    )

    if funs_path.exists():
        funs_lines = funs_path.read_text().splitlines(keepends=True)
        n_inst, n_call = apply_funs_renames(funs_lines, plan)
        funs_path.write_text("".join(funs_lines))
        print(
            f"[disambiguate-trait-fields] wrote {n_inst} instance-literal "
            f"and {n_call} method-call rename(s) to {funs_path}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
