#!/usr/bin/env python3
"""Strip non-normative declarations from a Lean Spec.lean.

Removes top-level blocks whose keyword is theorem/lemma/example/instance with
proof bodies, plus #guard/#eval/#check commands and notation declarations.
Keeps def/abbrev/structure/inductive/class/namespace/open/variable etc.

Block boundaries: a top-level declaration starts at column 0 with one of the
recognized keywords (possibly preceded by `private `, `protected `,
`noncomputable `, `partial `, `unsafe `, `mutual ` modifiers, or by an
attribute line `@[...]` or a doc comment `/-- ... -/` immediately above).
A block runs until the next top-level declaration start (or EOF).
Each block is classified by its keyword.
"""
import sys, re

DROP_KEYWORDS = {'theorem', 'lemma', 'example',
                 '#guard', '#eval', '#check', '#print', '#reduce'}
NOTATION_KEYWORDS = ('notation', 'scoped notation', 'local notation',
                     'infix ', 'infixl ', 'infixr ', 'prefix ', 'postfix ',
                     'scoped infix', 'scoped infixl', 'scoped infixr',
                     'scoped prefix', 'scoped postfix', 'macro_rules', 'syntax ')
KEEP_KEYWORDS = {'def', 'abbrev', 'instance', 'class', 'structure', 'inductive',
                 'namespace', 'end', 'open', 'section', 'variable', 'universe',
                 'attribute', 'set_option', 'import', 'mutual'}
MODIFIERS = ('private ', 'protected ', 'noncomputable ', 'partial ', 'unsafe ', '@')

DECL_RE = re.compile(
    r'^(?:(?:private|protected|noncomputable|partial|unsafe|nonrec)\s+)*'
    r'(?:mutual\s+)?'
    r'(def|abbrev|instance|class|structure|inductive|theorem|lemma|example|'
    r'namespace|end|open|section|variable|universe|attribute|'
    r'#guard|#eval|#check|#print|#reduce|#decompose|'
    r'scoped\s+notation|local\s+notation|notation|'
    r'scoped\s+infix|local\s+infix|infix|infixl|infixr|'
    r'prefix|postfix|macro_rules|syntax|'
    r'set_option\s+\S+\s+\S+\s+in\b)\b'
)

def is_decl_start(line):
    """Return the keyword if this line starts a top-level declaration; None otherwise."""
    m = DECL_RE.match(line)
    if not m:
        return None
    return m.group(1).strip()

def classify(keyword):
    """Return 'drop' for non-normative blocks, 'keep' otherwise."""
    if keyword in DROP_KEYWORDS:
        return 'drop'
    if keyword in ('notation', 'scoped notation', 'local notation',
                   'infix', 'infixl', 'infixr', 'prefix', 'postfix',
                   'scoped infix', 'scoped infixl', 'scoped infixr',
                   'scoped prefix', 'scoped postfix',
                   'macro_rules', 'syntax'):
        return 'drop'
    return 'keep'

def split_blocks(lines):
    """Split into list of (keyword|None, start_line_idx, lines)."""
    # Determine block starts. A block start is a decl line, possibly preceded by
    # attribute lines and/or a doc comment that we attach to the block.
    blocks = []
    n = len(lines)
    i = 0
    while i < n:
        # Find the next decl start
        j = i
        while j < n and is_decl_start(lines[j]) is None:
            j += 1
        # lines[i:j] is "between" content (or preamble); attach to current state
        # Find attribute lines / doc comment immediately above the decl
        if j < n:
            kw = is_decl_start(lines[j])
            # Walk backwards from j-1 to find contiguous attribute/doc-comment lines
            k = j
            while k > i:
                prev = lines[k-1].rstrip('\n')
                if re.match(r'^@\[', prev) or re.match(r'^/--', prev) or \
                   (prev.startswith('-/') and any('/--' in lines[m] for m in range(max(i,k-30), k))):
                    # attach this line to the upcoming decl
                    k -= 1
                    continue
                # Also attach multi-line doc comment: search backwards if we hit `-/`
                if prev.endswith('-/'):
                    # find matching /--
                    m = k - 1
                    while m > i and '/--' not in lines[m]:
                        m -= 1
                    if m >= i and '/--' in lines[m]:
                        k = m
                        continue
                break
            # lines[i:k] = preamble, classified as 'keep' (comments / blank lines)
            if k > i:
                blocks.append(('preamble', i, lines[i:k]))
            # Now find next decl start after j to know block end
            m = j + 1
            while m < n and is_decl_start(lines[m]) is None:
                m += 1
            blocks.append((kw, k, lines[k:m]))
            i = m
        else:
            # No more decls; tail is preamble-like
            if j > i:
                blocks.append(('preamble', i, lines[i:j]))
            i = j
    return blocks

def main(path):
    with open(path) as f:
        lines = f.readlines()
    blocks = split_blocks(lines)
    out = []
    for kw, _start, blines in blocks:
        if kw == 'preamble':
            out.extend(blines)
            continue
        cls = classify(kw)
        if cls == 'keep':
            out.extend(blines)
        # else drop — but preserve trailing blank line if any, so adjacent blocks stay separated
    sys.stdout.write(''.join(out))

if __name__ == '__main__':
    main(sys.argv[1])
