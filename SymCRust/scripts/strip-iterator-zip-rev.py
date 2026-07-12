#!/usr/bin/env python3
"""
Strip `zip := ...` and `rev := ...` field clauses from
`core.iter.traits.iterator.Iterator` impl records in extracted Lean files.

Background
----------
Charon emits Iterator trait impl records with 6 fields
(next, step_by, zip, enumerate, take, rev). The pinned Aeneas
`Aeneas.Std.Core.Iter` structure declares only 4 fields
(next, step_by, enumerate, take), so Lean rejects the extra
`zip` and `rev` fields with "is not a field of structure".

The standalone trait-method axioms
(`core.ops.range.RangeInclusive.Insts.CoreIterTraitsIteratorIterator.{zip,rev}`)
in `FunsExternal.lean` are unaffected and remain callable directly
(which is what every extracted call site does). Removing the
field clauses from the structure literal restores well-typedness.

If a future Aeneas pin adds those fields to the structure, this
script becomes a no-op and can be removed from the postprocess pipeline.
See AENEAS-BLOCKERS.md §3 for the upstream tracking note.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

STRIP_FIELDS = ("zip", "rev")
FIELD_RE = re.compile(r"^(\s+)(zip|rev)\s*:=")


def strip_iterator_extra_fields(text: str) -> tuple[str, int]:
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    i = 0
    n = len(lines)
    stripped = 0
    in_impl = False
    while i < n:
        line = lines[i]
        if (not in_impl
                and "core.iter.traits.iterator.Iterator" in line
                and ":= {" in line):
            in_impl = True
            out.append(line)
            i += 1
            continue
        if in_impl:
            if line.startswith("}"):
                in_impl = False
                out.append(line)
                i += 1
                continue
            m = FIELD_RE.match(line)
            if m:
                field_indent = len(m.group(1))
                i += 1
                while i < n:
                    nxt = lines[i]
                    if nxt.strip() == "":
                        i += 1
                        continue
                    lead = len(nxt) - len(nxt.lstrip())
                    if lead <= field_indent:
                        break
                    i += 1
                stripped += 1
                continue
        out.append(line)
        i += 1
    return "".join(out), stripped


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: strip-iterator-zip-rev.py <file.lean> [...]",
              file=sys.stderr)
        return 2
    rc = 0
    total = 0
    for arg in sys.argv[1:]:
        path = Path(arg)
        if not path.exists():
            print(f"[strip-iterator-zip-rev] missing file: {path}",
                  file=sys.stderr)
            rc = 1
            continue
        text = path.read_text()
        new_text, n = strip_iterator_extra_fields(text)
        if new_text == text:
            print(f"[strip-iterator-zip-rev] no change ({path})")
            continue
        path.write_text(new_text)
        total += n
        print(f"[strip-iterator-zip-rev] stripped {n} field clause(s) "
              f"from {path}")
    if total:
        print(f"[strip-iterator-zip-rev] total: {total} clause(s) stripped")
    return rc


if __name__ == "__main__":
    sys.exit(main())
