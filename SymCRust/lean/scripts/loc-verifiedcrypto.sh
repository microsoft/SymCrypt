#!/usr/bin/env bash
# loc-verifiedcrypto.sh — per-primitive LOC table for README-VERIFIEDCRYPTO.md
# and the per-primitive `Properties/<Algo>/VERIFIED.md` "file layout" tables.
#
# Methodology:
#
#   Single tool: `cloc` (1.94+; built-in Lean and Rust support). For every
#   bucket we report cloc's "code" line count (non-comment, non-blank
#   source lines). Comments and blanks are summed alongside for the
#   "code / comment / blank" detail table at the bottom.
#
#   Three columns per primitive:
#     - Rust code   : the SymCrypt-Rust impl files for that primitive,
#                     with `tests.rs` / `test.rs` excluded.
#     - Spec code   : cloc on the *normative* portion of each primitive's
#                     `Spec/<Algo>/Spec.lean`. "Normative" means we
#                     strip all theorem/lemma/example blocks,
#                     notation/infix/prefix/postfix/macro_rules/syntax
#                     declarations, and `#guard`/`#eval`/`#check`/`#print`/
#                     `#reduce` commands before counting, keeping only
#                     def/abbrev/instance/class/structure/inductive blocks
#                     plus structural lines (imports, namespaces, opens).
#                     Auxiliary files in `Spec/<Algo>/` (e.g. `XOF.lean`,
#                     `ArrayBridge.lean`, `Polynomials.lean`) are NOT
#                     normative formalizations of the standard and are
#                     excluded. The stripping is done by
#                     `scripts/strip-spec-nonnormative.py`.
#     - Proof code  : every `.lean` file under `Properties/<Algo>/` plus
#                     the matching `Properties/<Algo>.lean` aggregator.
#                     ML-KEM Intrinsics are split into the SSE2/NEON
#                     bucket and the AVX2 bucket reported separately.
#
# Cross-cutting files NOT attributed to any single primitive (reported as
# a separate row): `Properties/Axioms/`, `Properties/BitsAndBytes/`,
# `Properties/Iterators.lean`, `Properties/Stdlib.lean`.
#
# Usage: bash SymCRust/lean/scripts/loc-verifiedcrypto.sh [REPO_ROOT]

set -euo pipefail
script_dir=$(cd "$(dirname "$0")" && pwd)
repo_root="${1:-$(cd "$script_dir/../../.." && pwd)}"
cd "$repo_root"

# ----- cloc helpers -----
cloc_csv() { cloc --quiet --csv --include-lang=Lean,Rust "$@" 2>/dev/null; }
sum_field() { awk -F, -v F="$1" '/^[0-9]+,(Lean|Rust),/ { c+=$F } END { print c+0 }'; }

cloc_code()    { cloc_csv "$@" | sum_field 5; }
cloc_comment() { cloc_csv "$@" | sum_field 4; }
cloc_blank()   { cloc_csv "$@" | sum_field 3; }
cloc_files()   { cloc_csv "$@" | sum_field 2; }

triple() { # echoes "code comment blank files" for the given file list
  local code comment blank files
  read code comment blank files < <(cloc_csv "$@" \
    | awk -F, 'BEGIN{c=0; co=0; b=0; f=0}
               /^[0-9]+,(Lean|Rust),/ { f+=$2; b+=$3; co+=$4; c+=$5 }
               END { printf "%d %d %d %d\n", c, co, b, f }')
  echo "$code $comment $blank $files"
}

# ----- per-primitive file lists -----
# Each function emits a newline-separated file list on stdout.
rfiles() { for p in "$@"; do find $p -type f -name '*.rs' 2>/dev/null; done; }
lfiles() { for p in "$@"; do find $p -type f -name '*.lean' 2>/dev/null; done; }
exclude() { grep -vE "$1" || true; }

rust_sha3()     { rfiles SymCRust/src/sha3 | exclude '/tests?\.rs$'; }
rust_mlkem()    { ls SymCRust/src/mlkem/{ffi,hash,key,mlkem,ntt}.rs \
                     SymCRust/src/mlkem/ntt_xmm.rs SymCRust/src/mlkem/ntt_neon.rs \
                     SymCRust/src/mlkem/ntt_avx2.rs 2>/dev/null; }

spec_for() { # arg = primitive's Spec/ subdir name
  find SymCRust/lean/Spec/"$1" -name '*.lean' \
    -not -name 'TestVectors.lean' -not -name 'Tests.lean' -not -name '*Properties.lean' 2>/dev/null
}

# Normative-spec LOC: cloc on the stripped Spec.lean(s) for a primitive.
# Args = the Spec/*/Spec.lean files that constitute the normative spec.
spec_normative_code() {
  local total=0 tmp
  tmp=$(mktemp --suffix=.lean)
  for f in "$@"; do
    python3 "$script_dir/strip-spec-nonnormative.py" "$f" > "$tmp"
    local n
    n=$(cloc --quiet --csv --include-lang=Lean "$tmp" 2>/dev/null \
        | awk -F, '/^[0-9]+,Lean,/ {print $5; exit}')
    total=$(( total + ${n:-0} ))
  done
  rm -f "$tmp"
  echo "$total"
}

# Properties buckets (Lean files only — stray .rs bug-reports/ should not count).
prop_sha3()  { lfiles SymCRust/lean/Symcrust/Properties/SHA3 SymCRust/lean/Symcrust/Properties/SHA3.lean; }
prop_mlkem() { # all ML-KEM, including Intrinsics (scalar + SSE2/NEON + AVX2)
  lfiles SymCRust/lean/Symcrust/Properties/MLKEM SymCRust/lean/Symcrust/Properties/MLKEM.lean
}

prop_shared() {
  lfiles SymCRust/lean/Symcrust/Properties/Axioms \
         SymCRust/lean/Symcrust/Properties/BitsAndBytes \
         SymCRust/lean/Symcrust/Properties/Iterators.lean \
         SymCRust/lean/Symcrust/Properties/Stdlib.lean
}

# Hardware-intrinsic model (shared, not attributed to any one primitive):
#   Rust models  -> src/verify/intrinsics/
#   "spec"       -> the silicon axioms (vendor-doc semantics) in Intrinsics/Axioms/
#   proofs       -> Intrinsics/Properties/ + the BV/byte/simd support lemmas
rust_intrinsics() { rfiles SymCRust/src/verify/intrinsics; }
spec_intrinsics() { lfiles SymCRust/lean/Intrinsics/Axioms; }
prop_intrinsics() {
  lfiles SymCRust/lean/Intrinsics/Properties \
         SymCRust/lean/Intrinsics/Simd.lean \
         SymCRust/lean/Intrinsics/Bytes.lean \
         SymCRust/lean/Intrinsics/BVRealize.lean
}

# ----- table A: per-primitive headline (Rust / Spec / Proof code) -----
echo "=== A. README-VERIFIEDCRYPTO.md per-primitive headline (cloc code) ==="
printf '%-26s  %9s  %9s  %9s\n' Primitive 'Rust code' 'Spec code' 'Proof code'
printf -- '-%.0s' $(seq 1 60); echo

row() {
  local label="$1" rust="$2" spec="$3" prop="$4"
  printf '%-26s  %9s  %9s  %9s\n' "$label" \
    "$(cloc_code $rust)" "$(cloc_code $spec)" "$(cloc_code $prop)"
}

row_norm() { # row with normative-stripped spec(s)
  local label="$1" rust="$2" specs="$3" prop="$4"
  printf '%-26s  %9s  %9s  %9s\n' "$label" \
    "$(cloc_code $rust)" "$(spec_normative_code $specs)" "$(cloc_code $prop)"
}

row_norm "SHA-3 / SHAKE"      "$(rust_sha3)"  "SymCRust/lean/Spec/SHA3/Spec.lean"   "$(prop_sha3)"
row_norm "ML-KEM"             "$(rust_mlkem)" "SymCRust/lean/Spec/MLKEM/Spec.lean"  "$(prop_mlkem)"
row      "Intrinsics"         "$(rust_intrinsics)" "$(spec_intrinsics)" "$(prop_intrinsics)"

echo
echo "(Shared Lean infrastructure not attributed to any primitive:"
echo " Properties/Axioms/, Properties/BitsAndBytes/, Properties/Iterators.lean,"
echo " Properties/Stdlib.lean)"
printf '  shared                 : Proof code = %s\n' "$(cloc_code $(prop_shared))"

# ----- table B: per-primitive triple (code / comment / blank / files) -----
echo
echo "=== B. Per-primitive detail (code / comment / blank / files) ==="
printf '%-26s  %5s  %5s  %5s  %5s  |  %5s  %5s  %5s  %5s  |  %5s  %5s  %5s  %5s\n' \
  Primitive RstC RstO RstB RstF SpcC SpcO SpcB SpcF PrfC PrfO PrfB PrfF
printf -- '-%.0s' $(seq 1 110); echo

rowB() {
  local label="$1" rust="$2" spec="$3" prop="$4"
  local r s p
  r=$(triple $rust); s=$(triple $spec); p=$(triple $prop)
  printf '%-26s  %5s  %5s  %5s  %5s  |  %5s  %5s  %5s  %5s  |  %5s  %5s  %5s  %5s\n' \
    "$label" $r $s $p
}

rowB "SHA-3 / SHAKE"      "$(rust_sha3)"  "$(spec_for SHA3)"   "$(prop_sha3)"
rowB "ML-KEM"             "$(rust_mlkem)" "$(spec_for MLKEM)"  "$(prop_mlkem)"
rowB "Intrinsics"         "$(rust_intrinsics)" "$(spec_intrinsics)" "$(prop_intrinsics)"

# ----- table C: per-file VERIFIED.md "file layout" support -----
echo
echo "=== C. Per-file LOC for the VERIFIED.md file-layout tables ==="
echo "    (cloc code; pass a Properties subdir as additional argument to re-run for one bucket)"
for_subtree() {
  local label="$1"; shift
  echo "--- $label ---"
  for f in "$@"; do
    if [ -f "$f" ]; then
      printf '  %-60s  %5s\n' "$f" "$(cloc_code $f)"
    elif [ -d "$f" ]; then
      local sub
      sub=$(lfiles "$f")
      printf '  %-60s  %5s  (dir total, %s files)\n' "$f" \
        "$(cloc_code $sub)" "$(cloc_files $sub)"
    fi
  done
}
# A few illustrative dumps; users can add their own targets at the end of the script.
for_subtree "SHA3" \
  SymCRust/lean/Symcrust/Properties/SHA3/Basic.lean \
  SymCRust/lean/Symcrust/Properties/SHA3/Permutation.lean \
  SymCRust/lean/Symcrust/Properties/SHA3/Variants.lean \
  SymCRust/lean/Symcrust/Properties/SHA3/OneShot.lean \
  SymCRust/lean/Symcrust/Properties/SHA3/Streaming.lean 2>/dev/null

for_subtree "MLKEM Intrinsics" \
  SymCRust/lean/Symcrust/Properties/MLKEM/Intrinsics
